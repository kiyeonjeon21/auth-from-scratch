// Command authcode-pkce redoes chapter 00's login with no OIDC library.
//
// Same IdP, same client, same port, so 02-authcode-pkce/trace.md and
// 00-first-login-trace/trace.md line up and can be diffed. Anything that
// differs between them is something the library was doing that this code
// either does differently or does not do at all.
//
// Read 02-authcode-pkce/README.md before running.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kiyeonjeon/auth-from-scratch/internal/oidcclient"
	"github.com/kiyeonjeon/auth-from-scratch/internal/wiretrace"
)

var (
	issuer       = flag.String("issuer", "http://localhost:8080/realms/demo", "OIDC issuer URL")
	clientID     = flag.String("client-id", "demo-client", "OAuth client id")
	clientSecret = flag.String("client-secret", "demo-client-secret", "OAuth client secret")
	listen       = flag.String("listen", "localhost:5556", "address this app listens on")
	out          = flag.String("out", "02-authcode-pkce/trace.md", "where to write the trace")
	authMethod   = flag.String("client-auth", "client_secret_basic",
		"client_secret_basic | client_secret_post")
)

// clockLeeway is how much clock difference between us and the IdP we tolerate
// when checking `exp`. Zero breaks on healthy systems; large hides expiry.
const clockLeeway = 30 * time.Second

const scope = "openid profile email"

// login holds the one in-flight attempt. Chapter 00 explains why one slot is
// enough here and why a real client keys this by `state` in a session store.
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

	auth := oidcclient.ClientAuthMethod(*authMethod)
	if auth != oidcclient.AuthBasic && auth != oidcclient.AuthPost {
		log.Fatalf("-client-auth 는 %s 또는 %s", oidcclient.AuthBasic, oidcclient.AuthPost)
	}

	rec := wiretrace.New()
	hc := rec.Client()

	d, err := oidcclient.FetchDiscovery(context.Background(), hc, *issuer)
	if err != nil {
		log.Fatalf("디스커버리 실패: %v\n\nKeycloak이 떠 있는지 확인: make kc-up", err)
	}

	redirectURI := "http://" + *listen + "/callback"
	var cur login

	mux := http.NewServeMux()
	mux.HandleFunc("/", start(rec, d, redirectURI, &cur))
	mux.HandleFunc("/callback", callback(rec, hc, d, redirectURI, auth, &cur))

	log.Printf("IdP:        %s", d.Issuer)
	log.Printf("클라이언트:   %s (%s)", *clientID, redirectURI)
	log.Printf("클라이언트 인증: %s", auth)
	log.Printf("IdP가 지원하는 클라이언트 인증: %s", strings.Join(d.TokenEndpointAuthMethods, ", "))
	log.Printf("\n브라우저에서 열기 -> http://%s\n", *listen)

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	err = srv.ListenAndServe()
	if isAddrInUse(err) {
		log.Fatalf("%s 를 이미 누가 쓰고 있다.\n00 챕터 앱이 떠 있으면 먼저 끄고 다시 실행한다.", *listen)
	}
	log.Fatal(err)
}

// start builds the authorization request by hand and redirects the browser.
func start(rec *wiretrace.Recorder, d *oidcclient.Discovery, redirectURI string, cur *login) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		rec.Front("브라우저 → 앱: 로그인 시작", r.Method, absURL(r))

		cur.mu.Lock()
		cur.state = oidcclient.RandomURLSafe(32)
		cur.nonce = oidcclient.RandomURLSafe(32)
		cur.verifier = oidcclient.NewVerifier()
		cur.challenge = oidcclient.ChallengeS256(cur.verifier)
		state, nonce, challenge := cur.state, cur.nonce, cur.challenge
		cur.mu.Unlock()

		u, err := oidcclient.AuthorizeURL(d, oidcclient.AuthorizeParams{
			ClientID: *clientID, RedirectURI: redirectURI, Scope: scope,
			State: state, Nonce: nonce, Challenge: challenge,
		})
		if err != nil {
			httpError(w, "인가 URL 조립 실패", err)
			return
		}

		rec.Notes("여기서부터는 전부 내 코드가 만든 값이다", url.Values{
			"state":          {"randomURLSafe(32). 콜백에서 직접 대조한다"},
			"nonce":          {"randomURLSafe(32). ID 토큰 안의 값과 직접 대조한다"},
			"code_verifier":  {"randomURLSafe(32) = 43자. RFC 7636이 요구하는 최소 길이"},
			"code_challenge": {"challengeS256(verifier). SHA256 후 base64url, 패딩 없음"},
			"00과의 차이":        {"00에서는 verifier와 challenge를 x/oauth2가 만들어줬다"},
		})
		rec.Front("앱 → 브라우저: 인가 엔드포인트로 302", "GET", u)

		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

// callback validates the response and completes the exchange by hand.
func callback(
	rec *wiretrace.Recorder, hc *http.Client, d *oidcclient.Discovery,
	redirectURI string, auth oidcclient.ClientAuthMethod, cur *login,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.Front("브라우저 → 앱: 인가 응답 콜백", r.Method, absURL(r))
		q := r.URL.Query()

		if e := q.Get("error"); e != "" {
			httpError(w, "IdP가 에러를 돌려줌: "+e, fmt.Errorf("%s", q.Get("error_description")))
			return
		}

		cur.mu.Lock()
		want, nonce, verifier := cur.state, cur.nonce, cur.verifier
		cur.mu.Unlock()

		// Check 1: state. Nothing below this line is trustworthy without it.
		if want == "" || q.Get("state") != want {
			httpError(w, "state 불일치", fmt.Errorf("이 콜백은 내가 시작한 로그인이 아니다"))
			return
		}

		// RFC 9207. Keycloak sends `iss` on the callback; if it is there it
		// must match, which is what closes the mix-up attack when a client
		// talks to more than one IdP.
		issCheck := oidcclient.Check{Name: "iss (콜백 파라미터)", Detail: "IdP가 안 보냈다. RFC 9207 미지원", Deferred: true}
		if got := q.Get("iss"); got != "" {
			if got != d.Issuer {
				httpError(w, "콜백 iss 불일치", fmt.Errorf("%q 가 아니라 %q 에서 왔다", d.Issuer, got))
				return
			}
			issCheck = oidcclient.Check{Name: "iss (콜백 파라미터)", Detail: "응답이 온 IdP가 맞다 (RFC 9207)", Passed: true}
		}

		code := q.Get("code")
		if code == "" {
			httpError(w, "code 없음", fmt.Errorf("인가 응답에 code가 없다"))
			return
		}

		tok, err := oidcclient.ExchangeCode(r.Context(), hc, d, oidcclient.ExchangeParams{
			ClientID: *clientID, ClientSecret: *clientSecret, RedirectURI: redirectURI,
			Code: code, Verifier: verifier, Auth: auth,
		})
		if err != nil {
			httpError(w, "토큰 교환 실패", err)
			return
		}

		header, claims, checks, err := oidcclient.ValidateIDToken(
			tok.IDToken, d.Issuer, *clientID, nonce, clockLeeway, time.Now())
		// Prepend the checks that happened before we ever opened the token.
		checks = append([]oidcclient.Check{
			{Name: "state", Detail: "내 세션에 저장해둔 값과 일치", Passed: true},
			issCheck,
		}, checks...)
		if err != nil {
			renderChecks(w, checks, nil, nil, err)
			return
		}

		recordFindings(rec, d, auth, tok, header, claims, checks)
		rec.Header("ID 토큰 헤더 (내 파서로 디코딩)", toValues(header))
		rec.Claims("ID 토큰 클레임 (내 파서로 디코딩)", toValues(claims))

		// The access token gets the same treatment so 00 and 02 can be compared
		// block for block. It is not ours to validate - we are not its audience -
		// but reading it is how the missing `aud` from chapter 00 stays visible.
		if _, payload, _, err := oidcclient.SplitJWT(tok.AccessToken); err == nil {
			var m map[string]any
			if oidcclient.DecodeSegment(payload, &m) == nil {
				rec.Claims("액세스 토큰 클레임 (우리 것이 아니다. 읽기만)", mapToValues(m))
			}
		}

		if err := rec.WriteMarkdown(*out, "02 · 손으로 짠 Authorization Code + PKCE"); err != nil {
			httpError(w, "트레이스 쓰기 실패", err)
			return
		}
		log.Printf("\n로그인 성공. 검증 %d건. 트레이스: %s\n", len(checks), *out)
		log.Printf("00과 비교: make diff-traces\n")

		renderChecks(w, checks, claims, tok, nil)
	}
}

// recordFindings writes what this run showed, computed from the run itself.
func recordFindings(
	rec *wiretrace.Recorder, d *oidcclient.Discovery, auth oidcclient.ClientAuthMethod,
	tok *oidcclient.TokenResponse, h *oidcclient.JOSEHeader, c *oidcclient.IDClaims, checks []oidcclient.Check,
) {
	deferred := 0
	for _, ch := range checks {
		if ch.Deferred {
			deferred++
		}
	}
	if deferred > 0 {
		rec.Find(
			"검증을 다 통과했지만 서명은 아직 안 봤다",
			"이 앱은 ID 토큰의 글자를 읽어서 iss, aud, exp, nonce를 대조했다.\n"+
				"그런데 그 글자가 진짜 IdP가 쓴 것인지는 확인하지 않았다.\n\n"+
				"도장을 안 보고 서류 내용만 읽은 것과 같다. 내용은 누구나 쓸 수 있다.\n"+
				"지금 상태로는 공격자가 클레임을 마음대로 지어낸 토큰도 전부 통과한다.\n"+
				"03에서 JWKS로 도장을 대조해야 비로소 나머지 검증이 의미를 갖는다.",
			fmt.Sprintf("미검증 항목 %d건\nalg=%s 라고 토큰이 주장하지만, 그 주장 자체도 아직 안 믿을 이유가 없다", deferred, h.Alg),
			fmt.Sprintf("alg = %s\nkid = %s\n서명 = 검증 안 함 (03에서)", h.Alg, h.Kid),
		)
	}

	where := "Authorization 헤더"
	if auth == oidcclient.AuthPost {
		where = "요청 본문 (form 필드)"
	}
	rec.Find(
		"클라이언트 시크릿은 백채널 요청 딱 한 곳에만 나온다",
		fmt.Sprintf("이번 실행은 %s 방식이라 시크릿이 %s 에 실렸다.\n", auth, where)+
			"두 방식 모두 같은 연결, 같은 요청이다. 다른 건 요청의 어느 부분에 담기느냐뿐이다.\n\n"+
			"차이가 생기는 곳은 로그다. 본문은 프록시나 액세스 로그에 통째로 찍히는 설정이 흔하고,\n"+
			"헤더는 보통 마스킹 대상에 들어간다. 그래서 스펙이 basic 쪽을 권한다.",
		fmt.Sprintf("`%s` 사용. IdP가 지원한다고 광고한 목록: %s",
			auth, strings.Join(d.TokenEndpointAuthMethods, ", ")),
		"-client-auth 플래그로 바꿔가며 트레이스의 9번 요청을 비교해보라",
	)

	if c.AuthTime > 0 && c.Iat-c.AuthTime > 5 {
		gap := time.Duration(c.Iat-c.AuthTime) * time.Second
		rec.Find(
			"이번 로그인도 비밀번호를 묻지 않았다",
			fmt.Sprintf("마지막으로 실제 인증한 건 %s 전이다. IdP 세션이 살아있어서 그냥 통과했다.\n", gap.Round(time.Second))+
				"00에서 본 것과 같은 현상이고, 라이브러리를 걷어내도 달라지지 않는다.\n"+
				"이건 클라이언트 코드의 문제가 아니라 IdP 세션의 성질이기 때문이다.",
			"`auth_time` 과 `iat` 의 간격이 근거다.",
			fmt.Sprintf("auth_time = %d\niat       = %d", c.AuthTime, c.Iat),
		)
	}
}

// ------------------------------------------------------------------ helpers

func toValues(v any) url.Values {
	b, err := json.Marshal(v)
	if err != nil {
		return url.Values{"(오류)": {err.Error()}}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return url.Values{"(오류)": {err.Error()}}
	}
	return mapToValues(m)
}

func mapToValues(m map[string]any) url.Values {
	vals := url.Values{}
	for k, val := range m {
		out, err := json.Marshal(val)
		if err != nil {
			continue
		}
		vals.Set(k, strings.Trim(string(out), `"`))
	}
	return vals
}

func absURL(r *http.Request) *url.URL {
	return &url.URL{Scheme: "http", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
}

func httpError(w http.ResponseWriter, msg string, err error) {
	log.Printf("%s: %v", msg, err)
	http.Error(w, fmt.Sprintf("%s\n\n%v", msg, err), http.StatusBadRequest)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

func renderChecks(w http.ResponseWriter, checks []oidcclient.Check, c *oidcclient.IDClaims, tok *oidcclient.TokenResponse, failure error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	status := "로그인 성공"
	if failure != nil {
		status = "검증 실패"
		w.WriteHeader(http.StatusBadRequest)
	}
	data := map[string]any{
		"Status": status,
		"Checks": checks,
		"Fail":   failure,
		"Auth":   *authMethod,
	}
	if c != nil {
		data["Sub"] = c.Sub
		data["Aud"] = strings.Join(c.Aud, ", ")
	}
	if tok != nil {
		data["Scope"] = tok.Scope
		data["ExpiresIn"] = tok.ExpiresIn
	}
	_ = resultPage.Execute(w, data)
}

var resultPage = template.Must(template.New("r").Parse(`
<meta charset="utf-8">
<title>02 · 손으로 짠 Authorization Code + PKCE</title>
<style>
  :root { --fg:#1a1a1a; --muted:#6b6b6b; --bg:#fff; --panel:#f6f6f5; --line:#e4e4e2;
          --ok:#2b8a3e; --warn:#b4341c; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e6; --muted:#9a9a96; --bg:#161615; --panel:#232322; --line:#33332f;
            --ok:#69db7c; --warn:#e8845f; }
  }
  body { font: 15px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; max-width: 54rem;
         margin: 3rem auto; padding: 0 1.5rem; color: var(--fg); background: var(--bg); }
  h1 { font-size: 1.25rem; margin-bottom: 0.2rem; }
  h2 { font-size: 1rem; margin-top: 2.2rem; border-top: 1px solid var(--line); padding-top: 1.1rem; }
  p.sub { color: var(--muted); margin-top: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 0.6rem; }
  td { border-top: 1px solid var(--line); padding: 0.6rem 0.8rem 0.6rem 0; vertical-align: top;
       font-size: 14px; }
  td.m { white-space: nowrap; padding-right: 1.2rem; }
  .ok { color: var(--ok); } .todo { color: var(--warn); }
  pre { background: var(--panel); padding: 0.9rem; border-radius: 6px; overflow-x: auto; font-size: 13px; }
  code { background: var(--panel); padding: 0.1rem 0.35rem; border-radius: 3px; }
</style>
<h1>{{.Status}}</h1>
<p class="sub">이번엔 라이브러리가 아니라 내 코드가 검증했다</p>

<h2>내가 직접 한 검증</h2>
<table>
{{range .Checks}}
  <tr>
    <td class="m">{{if .Passed}}<span class="ok">통과</span>{{else if .Deferred}}<span class="todo">아직 안 함</span>{{else}}<span class="todo">실패</span>{{end}}</td>
    <td class="m"><code>{{.Name}}</code></td>
    <td>{{.Detail}}</td>
  </tr>
{{end}}
</table>
{{if .Fail}}<pre>{{.Fail}}</pre>{{end}}

{{if .Sub}}
<h2>결과</h2>
<table>
  <tr><td class="m"><code>sub</code></td><td>{{.Sub}}</td></tr>
  <tr><td class="m"><code>aud</code></td><td>{{.Aud}}</td></tr>
  <tr><td class="m">허용된 scope</td><td>{{.Scope}}</td></tr>
  <tr><td class="m">액세스 토큰 수명</td><td>{{.ExpiresIn}}초</td></tr>
  <tr><td class="m">클라이언트 인증</td><td>{{.Auth}}</td></tr>
</table>
{{end}}

<h2>다음</h2>
<ol>
  <li><code>02-authcode-pkce/trace.md</code> 를 연다.</li>
  <li><code>make diff-traces</code> 로 00의 트레이스와 비교한다. 남는 차이가 배울 것이다.</li>
  <li><code>-client-auth=client_secret_post</code> 로 다시 돌려서 시크릿이 옮겨가는 걸 본다.</li>
</ol>
`))
