// Command first-login-trace performs exactly one OIDC login using the standard
// Go libraries, and records every HTTP exchange to an annotated trace.md.
//
// This is the ONLY chapter allowed to use an OIDC library. The goal is not to
// learn the library, it is to see the finished shape of a login before taking
// it apart by hand in chapters 01-08.
//
// Read 00-first-login-trace/README.md before running.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kiyeonjeon/auth-from-scratch/internal/wiretrace"
)

var (
	issuer       = flag.String("issuer", "http://localhost:8080/realms/demo", "OIDC issuer URL")
	clientID     = flag.String("client-id", "demo-client", "OAuth client id")
	clientSecret = flag.String("client-secret", "demo-client-secret", "OAuth client secret")
	// 5556 rather than 3000: 3000 collides with almost every other dev server,
	// and a redirect_uri mismatch is a confusing first failure to debug.
	listen = flag.String("listen", "localhost:5556", "address this app listens on")
	out    = flag.String("out", "00-first-login-trace/trace.md", "where to write the trace")
)

// login is the state of the single in-flight login attempt.
//
// A real client keys this by `state` in a session store, because many users
// log in at once and a browser can have several tabs mid-flow. One global
// slot is enough here and keeps the moving parts visible.
type login struct {
	mu        sync.Mutex
	state     string
	nonce     string
	verifier  string
	challenge string
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	rec := wiretrace.New()
	ctx := oidc.ClientContext(context.Background(), rec.Client())

	// Discovery. One GET that replaces every hardcoded endpoint URL.
	provider, err := oidc.NewProvider(ctx, *issuer)
	if err != nil {
		log.Fatalf("디스커버리 실패: %v\n\nKeycloak이 떠 있는지 확인: make kc-up", err)
	}

	redirectURL := "http://" + *listen + "/callback"
	conf := &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: *clientID})

	var cur login
	mux := http.NewServeMux()
	mux.HandleFunc("/", start(rec, conf, &cur))
	mux.HandleFunc("/callback", callback(rec, ctx, conf, idTokenVerifier, &cur))

	log.Printf("IdP:      %s", *issuer)
	log.Printf("클라이언트: %s (%s)", *clientID, redirectURL)
	log.Printf("\n브라우저에서 열기 -> http://%s\n", *listen)
	log.Printf("개발자도구 네트워크 탭에서 Preserve log를 켜두면 브라우저-IdP 구간까지 같이 볼 수 있다.\n")

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// start builds the authorization request and redirects the browser to the IdP.
func start(rec *wiretrace.Recorder, conf *oauth2.Config, cur *login) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		rec.Front("브라우저 → 앱: 로그인 시작", r.Method, absURL(r))

		cur.mu.Lock()
		cur.state = randomString(32)
		cur.nonce = randomString(32)
		// x/oauth2 generates the PKCE verifier and derives the S256 challenge.
		// It does NOT generate state or nonce: those are still on us.
		cur.verifier = oauth2.GenerateVerifier()
		state, nonce, verifier := cur.state, cur.nonce, cur.verifier
		cur.mu.Unlock()

		authURL := conf.AuthCodeURL(state,
			oidc.Nonce(nonce),
			oauth2.S256ChallengeOption(verifier),
		)
		parsed, err := url.Parse(authURL)
		if err != nil {
			httpError(w, "인가 URL 파싱 실패", err)
			return
		}
		cur.mu.Lock()
		cur.challenge = parsed.Query().Get("code_challenge")
		cur.mu.Unlock()

		rec.Notes("이 시점에 누가 무엇을 만들었나", url.Values{
			"state":         {"앱이 생성. 라이브러리가 안 해준다. 콜백에서 직접 대조해야 함"},
			"nonce":         {"앱이 생성. 라이브러리가 안 해준다. ID 토큰과 직접 대조해야 함"},
			"code_verifier": {"x/oauth2가 생성 (GenerateVerifier). 아직 네트워크로 안 나감"},
			"code_challenge": {"x/oauth2가 verifier에서 S256으로 유도. " +
				"지금 나가는 건 해시뿐이라 프론트채널에서 새도 원본을 모른다"},
		})
		rec.Front("앱 → 브라우저: 인가 엔드포인트로 302", "GET", parsed)

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// callback receives the authorization response and completes the login.
func callback(
	rec *wiretrace.Recorder,
	ctx context.Context,
	conf *oauth2.Config,
	idTokenVerifier *oidc.IDTokenVerifier,
	cur *login,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.Front("브라우저 → 앱: 인가 응답 콜백", r.Method, absURL(r))

		if e := r.URL.Query().Get("error"); e != "" {
			httpError(w, "IdP가 에러를 돌려줌: "+e, fmt.Errorf("%s", r.URL.Query().Get("error_description")))
			return
		}

		cur.mu.Lock()
		want, nonce, verifier, challenge := cur.state, cur.nonce, cur.verifier, cur.challenge
		cur.mu.Unlock()

		// Defence #1: state. Proves this callback belongs to a flow we started.
		if want == "" || r.URL.Query().Get("state") != want {
			httpError(w, "state 불일치", fmt.Errorf("이 콜백은 내가 시작한 로그인이 아니다"))
			return
		}

		// Back channel. The code, the secret and the verifier all travel here,
		// never through the browser.
		tok, err := conf.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			httpError(w, "토큰 교환 실패", err)
			return
		}

		rawIDToken, ok := tok.Extra("id_token").(string)
		if !ok {
			httpError(w, "ID 토큰 없음", fmt.Errorf("scope에 openid가 빠졌을 때 이렇게 된다"))
			return
		}

		// Verify triggers the JWKS fetch, so it shows up in the trace here.
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			httpError(w, "ID 토큰 검증 실패", err)
			return
		}

		// Defence #2: nonce. Proves this ID token was minted for our request.
		if idToken.Nonce != nonce {
			httpError(w, "nonce 불일치", fmt.Errorf("리플레이된 ID 토큰일 수 있다"))
			return
		}

		rec.Notes("라이브러리가 Verify() 안에서 대신 해준 검증", url.Values{
			"서명":    {"JWKS의 공개키로 검증. kid로 키를 골랐다"},
			"iss":   {"디스커버리 문서의 issuer와 일치하는지"},
			"aud":   {"내 client_id가 들어있는지"},
			"exp":   {"만료되지 않았는지"},
			"nonce": {"**하지 않는다.** idToken.Nonce를 꺼내주기만 하고 대조는 앱 몫"},
			"at_hash": {"액세스 토큰이 같이 왔으면 해시 대조. " +
				"Authorization Code flow에서는 백채널로 받으므로 실익이 적다"},
		})
		rec.Header("ID 토큰 헤더", jwtHeader(rawIDToken))
		rec.Claims("ID 토큰 클레임 (aud를 보라. 이 토큰의 대상은 클라이언트인 나다)", jwtPayload(rawIDToken))

		// The access token is where the interesting absence is: with no
		// audience mapper configured, Keycloak issues it without `aud` at all.
		// Naming that gap here is the setup for chapter 03.
		access := jwtPayload(tok.AccessToken)
		title := "액세스 토큰 클레임 (aud가 ID 토큰과 다르다)"
		if access.Get("aud") == "" {
			title = "액세스 토큰 클레임 (**aud가 아예 없다.** 그럼 리소스 서버는 무엇을 보고 자기 것이라 판단하나? -> 03)"
		}
		rec.Claims(title, access)

		findPKCESplit(rec, challenge, verifier)
		findMissingAudience(rec, access)
		findSilentReauth(rec, jwtPayload(rawIDToken))
		findNonceIsOnUs(rec, nonce)

		if err := rec.WriteMarkdown(*out, "첫 로그인 와이어 트레이스"); err != nil {
			httpError(w, "트레이스 쓰기 실패", err)
			return
		}
		log.Printf("\n로그인 성공. 발견 %d건. 트레이스: %s\n", len(rec.Findings()), *out)

		var claims map[string]any
		_ = idToken.Claims(&claims)
		pretty, _ := json.MarshalIndent(claims, "", "  ")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = resultPage.Execute(w, map[string]any{
			"Out":       *out,
			"Subject":   idToken.Subject,
			"Claims":    string(pretty),
			"Expiry":    tok.Expiry.Format("15:04:05"),
			"ExpiresIn": korDur(time.Until(tok.Expiry).Round(time.Minute)),
			"Findings":  rec.Findings(),
		})
	}
}

// ----------------------------------------------------------------- findings
//
// Each of these derives its claim from what this run actually produced. If the
// condition does not hold, nothing is reported. A finding that fires on data
// it cannot see would be worse than no finding at all.

// findPKCESplit shows the same secret leaving by two different channels.
func findPKCESplit(rec *wiretrace.Recorder, challenge, verifier string) {
	if challenge == "" || verifier == "" {
		return
	}
	rec.Find(
		"비밀번호를 통째로 맡기지 않고, 갈아서 만든 가루만 미리 맡겼다",
		"앱은 로그인을 시작할 때 아무도 못 알아볼 비밀 단어를 하나 만들었다.\n"+
			"그런데 그 단어를 그대로 보내지 않고, **믹서에 갈아서 만든 가루만** 먼저 보냈다. 아래 위쪽 줄이다.\n"+
			"가루는 브라우저 주소창을 타고 갔으니 누가 훔쳐봤을 수도 있다. 그래도 괜찮다.\n"+
			"**가루를 되돌려서 원래 단어를 알아낼 방법은 없기 때문이다.**\n\n"+
			"진짜 단어는 나중에, 앱과 서버가 둘이서만 쓰는 통로로 보냈다. 아래쪽 줄이다.\n"+
			"서버는 받은 단어를 똑같이 갈아보고 가루가 일치하는지 확인한다.\n\n"+
			"그래서 주소창을 훔쳐본 사람은 가루밖에 못 봤고, 원래 단어를 모르니 아무것도 못 한다.",
		"해시(`code_challenge`)는 프론트채널로, 원본(`code_verifier`)은 백채널로 나갔다.\n"+
			"주소창에서 `code`를 탈취해도 `code_verifier`가 없으면 토큰으로 교환할 수 없다.\n"+
			"이 비대칭 하나가 PKCE 전부다.",
		"front (브라우저 주소창)  code_challenge="+challenge+"   <- 갈아 만든 가루\n"+
			"back  (서버끼리만)      code_verifier ="+verifier+"   <- 진짜 단어",
	)
}

// findMissingAudience reports an access token that names no audience.
func findMissingAudience(rec *wiretrace.Recorder, access url.Values) {
	if access.Get("aud") != "" {
		return
	}
	rec.Find(
		"방금 받은 출입증에 '어디 출입증인지'가 안 적혀 있다",
		"출입증(액세스 토큰)은 나중에 다른 서버한테 보여주고 뭔가를 요청할 때 쓰는 것이다.\n"+
			"그런데 이 출입증에는 **어느 건물 것인지가 안 적혀 있다.**\n\n"+
			"도서관 출입증에 '도서관'이라고 안 써 있다고 생각해보자.\n"+
			"수영장 직원이 그걸 받으면, 우리 것인지 남의 것인지 판단할 방법이 없다.\n"+
			"그래서 도서관에서 받은 출입증을 수영장에 내밀어도 통과될 수 있다.\n\n"+
			"이게 Keycloak의 기본 설정이다. 따로 손대지 않으면 이렇게 나온다.\n"+
			"03에서 '받는 쪽'을 만들 때 이 문제를 정면으로 다룬다.",
		"액세스 토큰에 `aud` 클레임이 없다. 리소스 서버는 토큰만으로 자신이 대상인지 판정할 수 없다.\n"+
			"audience mapper를 붙이지 않은 Keycloak의 기본 동작이다.\n"+
			"03의 audience confusion은 남의 이야기가 아니라 지금 이 realm의 상태다.",
		"azp = "+access.Get("azp")+"   <- 누가 이 출입증을 받아갔는지는 적혀 있다\naud = (없음)        <- 어디에 쓰는 것인지는 안 적혀 있다",
	)
}

// findSilentReauth reports a login that reused an existing IdP session.
// auth_time older than iat means the user was not asked for anything.
func findSilentReauth(rec *wiretrace.Recorder, id url.Values) {
	authTime, err1 := strconv.ParseInt(id.Get("auth_time"), 10, 64)
	issuedAt, err2 := strconv.ParseInt(id.Get("iat"), 10, 64)
	if err1 != nil || err2 != nil {
		return
	}
	gap := issuedAt - authTime
	if gap < 5 {
		return // fresh authentication, nothing surprising
	}
	ago := korDur(time.Duration(gap) * time.Second)
	rec.Find(
		"방금 로그인은 비밀번호를 한 번도 안 물어봤다",
		"놀이공원에 들어갈 때 손등에 도장을 찍어준다. 잠깐 나갔다 들어올 땐 도장만 보여주면 표를 다시 안 산다.\n"+
			"방금 그게 일어났다. 로그인 창이 안 떴을 것이다.\n"+
			fmt.Sprintf("실제로 비밀번호를 친 건 **%s 전**이고, 그때 찍은 도장이 아직 유효해서 그냥 통과했다.\n\n", ago)+
			"문제는 앱한테 도착한 소식이 '로그인 됐어요' 한 줄뿐이라는 것이다.\n"+
			"**지금 막 확인한 건지, 아까 찍은 도장만 보고 통과시킨 건지 앱은 구분하지 못한다.**\n"+
			"구분하려면 토큰 안에 같이 온 '마지막으로 진짜 확인한 시각'을 직접 꺼내 봐야 한다.\n\n"+
			"돈이 나가는 화면이면 이게 문제가 된다.\n"+
			"로그인한 채로 자리를 비웠다면, 옆사람은 비밀번호 없이 결제까지 갈 수 있다.\n"+
			"그래서 중요한 순간에는 '도장 말고 지금 다시 확인해줘'라고 따로 요청해야 한다.",
		fmt.Sprintf("IdP 세션이 살아있어서 재인증이 생략됐다. 마지막 실제 인증은 %s 전이다.\n", ago)+
			"앱이 받은 것은 그냥 '로그인 성공'이다. **재인증 여부를 알려면 `auth_time`을 직접 봐야 한다.**\n"+
			"결제 직전에 비밀번호를 다시 받고 싶다면 `max_age` 또는 `prompt=login`이 필요한 이유다.\n"+
			"05에서 '로그아웃했는데 다시 눌렀더니 그냥 들어가진다'가 생기는 것도 같은 세션이다.",
		fmt.Sprintf("auth_time = %d  <- 마지막으로 진짜 비밀번호를 친 시각\n"+
			"iat       = %d  <- 이번 토큰이 발급된 시각\n"+
			"acr       = %s           <- 0이면 '이번엔 확인 안 했다'는 뜻",
			authTime, issuedAt, id.Get("acr")),
	)
}

// findNonceIsOnUs states where the library's guarantees stop.
func findNonceIsOnUs(rec *wiretrace.Recorder, nonce string) {
	rec.Find(
		"라이브러리 검사를 다 통과해도, 남이 쓰던 신분증일 수 있다",
		"앱은 로그인을 시작할 때 아무도 모르는 낙서를 하나 적어서 같이 보냈다. 아래 값이다.\n"+
			"제대로 된 답이라면 그 낙서가 그대로 돌아와야 한다.\n\n"+
			"라이브러리는 돌아온 신분증을 꽤 꼼꼼히 본다.\n"+
			"위조가 아닌지(도장), 어디서 발급했는지, 나한테 준 게 맞는지, 기한이 지났는지까지 다 본다.\n"+
			"**그런데 '내 낙서가 들어있는지'는 안 본다.**\n\n"+
			"그래서 누가 예전에 받았던 **진짜** 신분증을 복사해서 다시 내밀면, 그 검사들은 전부 통과한다.\n"+
			"막는 건 앱 코드 한 줄이다. 그 줄을 지우면 라이브러리는 아무 불평도 하지 않는다.\n\n"+
			"'라이브러리 썼으니 안전하다'가 어디서 끝나는지가 정확히 여기다.",
		"라이브러리는 서명, `iss`, `aud`, `exp`까지 검증하고 토큰을 돌려준다. **`nonce` 대조는 하지 않는다.**\n"+
			"그걸 막는 것은 `main.go`의 앱 코드 한 줄이다. 그 줄을 지우면 검증은 여전히 전부 통과한다.",
		"보낸 낙서 (nonce): "+nonce+"\n대조하는 곳:       main.go 의 idToken.Nonce != nonce",
	)
}

// korDur renders a duration the way a person would say it. Go's "18m44s" is
// noise in a page whose whole point is being readable without background.
func korDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d초", int(d.Seconds()))
	case d < time.Hour:
		m, s := int(d.Minutes()), int(d.Seconds())%60
		if s == 0 {
			return fmt.Sprintf("%d분", m)
		}
		return fmt.Sprintf("%d분 %d초", m, s)
	default:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("%d시간", h)
		}
		return fmt.Sprintf("%d시간 %d분", h, m)
	}
}

// ------------------------------------------------------------------ helpers

// jwtHeader decodes the header of a JWT without verifying anything.
// Decoding an unverified token is fine here and only here: we already verified
// the ID token above, and reading is the whole point of the chapter.
func jwtHeader(token string) url.Values { return decodeSegment(token, 0) }

// jwtPayload decodes the claims of a JWT without verifying anything.
func jwtPayload(token string) url.Values { return decodeSegment(token, 1) }

func decodeSegment(token string, i int) url.Values {
	parts := strings.Split(token, ".")
	if len(parts) < i+1 {
		return url.Values{"(오류)": {"JWT 형식이 아니다. 불투명 토큰일 수 있다"}}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		return url.Values{"(오류)": {"base64url 디코딩 실패: " + err.Error()}}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return url.Values{"(오류)": {"JSON 파싱 실패: " + err.Error()}}
	}
	vals := url.Values{}
	for k, v := range m {
		b, err := json.Marshal(v)
		if err != nil {
			vals.Set(k, fmt.Sprintf("%v", v))
			continue
		}
		vals.Set(k, strings.Trim(string(b), `"`))
	}
	return vals
}

func absURL(r *http.Request) *url.URL {
	return &url.URL{Scheme: "http", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means we must not continue.
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func httpError(w http.ResponseWriter, msg string, err error) {
	log.Printf("%s: %v", msg, err)
	http.Error(w, fmt.Sprintf("%s\n\n%v", msg, err), http.StatusBadRequest)
}

// resultPage leads with the findings, not the claims dump. "Login succeeded"
// is not worth a page; what the login quietly revealed is.
// rich renders the tiny slice of Markdown the findings use (**bold** and
// `code`) as HTML. Findings are written once and rendered into both trace.md
// and this page, so the markers have to survive both.
//
// Escaping happens first, so a finding built from token data can never inject
// markup.
func rich(s string) template.HTML {
	out := template.HTMLEscapeString(s)
	out = wrapPairs(out, "**", "<strong>", "</strong>")
	out = wrapPairs(out, "`", "<code>", "</code>")
	return template.HTML(out)
}

// wrapPairs replaces balanced pairs of marker with open/close tags. An unpaired
// trailing marker is left as literal text.
func wrapPairs(s, marker, open, close string) string {
	parts := strings.Split(s, marker)
	if len(parts) < 3 {
		return s
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			if i%2 == 1 && i < len(parts)-1 {
				b.WriteString(open)
			} else if i%2 == 0 {
				b.WriteString(close)
			} else {
				b.WriteString(marker)
			}
		}
		b.WriteString(p)
	}
	return b.String()
}

var resultPage = template.Must(template.New("result").Funcs(template.FuncMap{
	"add":  func(a, b int) int { return a + b },
	"rich": rich,
}).Parse(`
<meta charset="utf-8">
<title>첫 로그인 트레이스</title>
<style>
  :root { --fg:#1a1a1a; --muted:#6b6b6b; --bg:#fff; --panel:#f6f6f5; --line:#e4e4e2; --mark:#b4341c; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e6; --muted:#9a9a96; --bg:#161615; --panel:#232322; --line:#33332f; --mark:#e8845f; }
  }
  body { font: 15px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; max-width: 54rem;
         margin: 3rem auto; padding: 0 1.5rem; color: var(--fg); background: var(--bg); }
  h1 { font-size: 1.25rem; margin-bottom: 0.2rem; }
  h2 { font-size: 1rem; margin-top: 2.4rem; border-top: 1px solid var(--line); padding-top: 1.2rem; }
  p.sub { color: var(--muted); margin-top: 0; }
  pre { background: var(--panel); padding: 0.9rem 1rem; border-radius: 6px; overflow-x: auto;
        font-size: 13px; line-height: 1.5; }
  code { background: var(--panel); padding: 0.1rem 0.35rem; border-radius: 3px; }
  .f { margin: 1.8rem 0; padding-left: 1rem; border-left: 3px solid var(--mark); }
  .f h3 { font-size: 1rem; margin: 0 0 0.6rem; }
  .f p { margin: 0 0 0.8rem; white-space: pre-line; }
  strong { color: var(--mark); }
  ol { padding-left: 1.3rem; } li { margin: 0.55rem 0; }
  table { border-collapse: collapse; margin: 1rem 0; width: 100%; }
  td { border-top: 1px solid var(--line); padding: 0.65rem 0.9rem 0.65rem 0;
       vertical-align: top; font-size: 14px; }
  td:first-child { white-space: nowrap; padding-right: 1.6rem; }
  .t { color: var(--muted); font-size: 12px; }
  details { margin-top: 0.9rem; } summary { cursor: pointer; color: var(--muted); font-size: 13px; }
  .tech { color: var(--muted); font-size: 13.5px; margin-top: 0.6rem; }
</style>
<h1>로그인 성공</h1>
<p class="sub">그래서 방금 무슨 일이 있었고, 무엇을 봐야 하나</p>

<h2>1. 방금 무슨 일이 있었나</h2>
<p>등장인물은 셋이다.</p>
<table>
  <tr><td><b>너</b></td><td>브라우저 앞에 앉아 있는 사람</td></tr>
  <tr><td><b>앱</b> (localhost:5556)</td><td>네가 들어가려는 곳. 네가 누군지 모른다</td></tr>
  <tr><td><b>확인 기관</b> (localhost:8080)</td><td>Keycloak. 사람을 확인해주고 증명서를 발급하는 곳</td></tr>
</table>
<ol>
  <li>너는 앱에 들어가려고 했다.</li>
  <li>앱은 "이 사람이 누군지 모르겠다"며 너를 <b>확인 기관으로 보냈다.</b>
      앱은 네 비밀번호를 보지도 않고, 볼 수도 없다.</li>
  <li>확인 기관이 확인을 끝내고 너를 앱으로 돌려보내면서 <b>교환권</b> 한 장을 쥐어줬다.
      교환권 자체는 아무 정보도 없는 종이쪼가리다.</li>
  <li>앱은 그 교환권을 들고 <b>혼자 확인 기관에 직접 찾아가</b> 증명서 2장으로 바꿔왔다.
      이 왕복은 브라우저를 거치지 않는다.</li>
  <li>지금 이 화면은 앱이 그 증명서를 검사한 결과다.</li>
</ol>

<h2>2. 앱이 받아온 증명서 2장</h2>
<table>
  <tr><td><b>신분증</b><br><span class="t">ID 토큰</span></td>
      <td>"이 사람은 alice가 맞다"<br>
          <b>앱이 보려고</b> 받은 것. 다른 데 보내면 안 된다.</td></tr>
  <tr><td><b>출입증</b><br><span class="t">액세스 토큰</span></td>
      <td>"이걸 가진 사람은 여기까지 해도 된다"<br>
          나중에 <b>다른 서버에 보여주려고</b> 받은 것.</td></tr>
</table>

<h2>3. 화면 맨 위 숫자가 뭐냐면</h2>
<table>
  <tr><td><code>sub</code><br>{{.Subject}}</td>
      <td><b>네 고유 번호다.</b> 이름도 이메일도 나중에 바뀔 수 있지만 이 번호는 안 바뀐다.
          그래서 앱은 사람을 구분할 때 이메일이 아니라 이걸 써야 한다.</td></tr>
  <tr><td><code>만료</code><br>{{.Expiry}}</td>
      <td><b>출입증 유효시간이다.</b> {{.ExpiresIn}} 뒤면 못 쓴다.
          이렇게 짧게 주는 이유는, 누가 훔쳐가도 금방 쓸모없어지게 하려고다.</td></tr>
</table>

<h2>4. 이번 실행에서 걸린 것 {{len .Findings}}건</h2>
<p class="sub">미리 써둔 문장이 아니라, 방금 오간 증명서에서 계산된 것이다.
조건이 안 맞으면 그 항목은 아예 안 나온다.</p>
{{range $i, $f := .Findings}}
<div class="f">
  <h3>{{add $i 1}}. {{rich $f.Headline}}</h3>
  <p>{{rich $f.Plain}}</p>
  {{if $f.Evidence}}<pre>{{$f.Evidence}}</pre>{{end}}
  <details>
    <summary>정확한 용어로</summary>
    <p class="tech">{{rich $f.Body}}</p>
  </details>
</div>
{{end}}

<h2>다음</h2>
<ol>
  <li><code>{{.Out}}</code> 를 연다. 맨 위 "먼저 볼 것"에 위 내용이 그대로 있고, 그 아래가 왕복 전체다.</li>
  <li>표에서 <code>**TODO**</code> 로 남은 값을 찾는다. 용어집에 없는 것이라 파고들 지점이다.</li>
  <li>답을 <code>00-first-login-trace/ANSWERS.md</code> 에 자기 말로 적는다.</li>
</ol>

<details>
  <summary>ID 토큰 클레임 원본</summary>
  <pre>{{.Claims}}</pre>
</details>
`))
