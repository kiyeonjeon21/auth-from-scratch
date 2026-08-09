// Command logout shows why logging out is harder than logging in.
//
// Chapter 03 ended a session with one map delete. Add an IdP and the state is
// suddenly in three places at once - the browser cookie, this app's session,
// and the IdP's SSO session - and clearing only the one you own leaves the
// user logged in.
//
// Two RPs run side by side so the third case is visible: when a user logs out
// of RP A, RP B has to find out somehow. That is what back-channel logout is.
//
// Read 04-logout/README.md before running.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kiyeonjeon/auth-from-scratch/internal/oidcclient"
)

var (
	issuer  = flag.String("issuer", "http://localhost:8080/realms/demo", "OIDC issuer URL")
	listenA = flag.String("listen-a", "localhost:5560", "RP A 주소")
	listenB = flag.String("listen-b", "localhost:5561", "RP B 주소")
)

const (
	clockLeeway = 30 * time.Second
	scope       = "openid profile email"
)

// rp is one relying party: its own local session, its own client credentials.
//
// Each RP keeps a session exactly like chapter 03 did. The IdP knows nothing
// about these; that gap is the whole subject of this chapter.
type rp struct {
	name         string
	clientID     string
	clientSecret string
	base         string
	peer         string
	disc         *oidcclient.Discovery
	hc           *http.Client

	mu    sync.Mutex
	sess  map[string]*rpSession // our session id -> session
	bySID map[string]string     // IdP session id (sid) -> our session id
	pend  map[string]*pending   // state -> in-flight login
	log   []string              // what happened, newest first
}

// rpSession is this RP's own login state.
//
// Sid is the key that makes back-channel logout work: it is the IdP's session
// identifier, carried in the ID token, and it is what a logout token names.
// Without storing it we would be told "session X ended" and have no idea which
// of our sessions that is.
type rpSession struct {
	ID       string
	User     string
	Sid      string
	IDToken  string // kept for id_token_hint on RP-initiated logout
	LoggedAt time.Time
}

type pending struct {
	nonce    string
	verifier string
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	hc := &http.Client{Timeout: 15 * time.Second}
	d, err := oidcclient.FetchDiscovery(context.Background(), hc, *issuer)
	if err != nil {
		log.Fatalf("디스커버리 실패: %v\n\nKeycloak이 떠 있는지 확인: make kc-up", err)
	}
	if d.EndSessionEndpoint == "" {
		log.Fatal("이 IdP는 end_session_endpoint를 광고하지 않는다")
	}

	a := newRP("RP A", "demo-rp-a", "demo-rp-a-secret", "http://"+*listenA, "http://"+*listenB, d, hc)
	b := newRP("RP B", "demo-rp-b", "demo-rp-b-secret", "http://"+*listenB, "http://"+*listenA, d, hc)

	srvA := &http.Server{Addr: *listenA, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	srvB := &http.Server{Addr: *listenB, Handler: b.routes(), ReadHeaderTimeout: 5 * time.Second}

	log.Printf("RP A   %s", a.base)
	log.Printf("RP B   %s", b.base)
	log.Printf("IdP    %s", d.Issuer)
	log.Printf("\n둘 다 로그인한 뒤, A에서 각 로그아웃 버튼을 눌러보라.\n")

	go serve(srvB)
	go serve(srvA)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srvA.Shutdown(ctx)
	_ = srvB.Shutdown(ctx)
}

func serve(s *http.Server) {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if errors.Is(err, syscall.EADDRINUSE) {
			log.Fatalf("%s 를 이미 누가 쓰고 있다.", s.Addr)
		}
		log.Fatal(err)
	}
}

func newRP(name, id, secret, base, peer string, d *oidcclient.Discovery, hc *http.Client) *rp {
	return &rp{
		name: name, clientID: id, clientSecret: secret, base: base, peer: peer,
		disc: d, hc: hc,
		sess: map[string]*rpSession{}, bySID: map[string]string{}, pend: map[string]*pending{},
	}
}

func (p *rp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.home)
	mux.HandleFunc("/login", p.login)
	mux.HandleFunc("/callback", p.callback)
	mux.HandleFunc("/logout-local", p.logoutLocal)
	mux.HandleFunc("/logout-rp-initiated", p.logoutRPInitiated)
	mux.HandleFunc("/post-logout", p.postLogout)
	mux.HandleFunc("/backchannel-logout", p.backchannelLogout)
	return mux
}

// ------------------------------------------------------------------- login

func (p *rp) login(w http.ResponseWriter, r *http.Request) {
	state := oidcclient.RandomURLSafe(24)
	nonce := oidcclient.RandomURLSafe(24)
	verifier := oidcclient.NewVerifier()

	p.mu.Lock()
	p.pend[state] = &pending{nonce: nonce, verifier: verifier}
	p.mu.Unlock()

	u, err := oidcclient.AuthorizeURL(p.disc, oidcclient.AuthorizeParams{
		ClientID: p.clientID, RedirectURI: p.base + "/callback", Scope: scope,
		State: state, Nonce: nonce, Challenge: oidcclient.ChallengeS256(verifier),
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *rp) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, e+": "+q.Get("error_description"), 400)
		return
	}

	p.mu.Lock()
	pend, ok := p.pend[q.Get("state")]
	delete(p.pend, q.Get("state"))
	p.mu.Unlock()
	if !ok {
		http.Error(w, "state 불일치", 400)
		return
	}

	tok, err := oidcclient.ExchangeCode(r.Context(), p.hc, p.disc, oidcclient.ExchangeParams{
		ClientID: p.clientID, ClientSecret: p.clientSecret, RedirectURI: p.base + "/callback",
		Code: q.Get("code"), Verifier: pend.verifier, Auth: oidcclient.AuthBasic,
	})
	if err != nil {
		http.Error(w, "토큰 교환 실패: "+err.Error(), 400)
		return
	}
	_, claims, _, err := oidcclient.ValidateIDToken(
		tok.IDToken, p.disc.Issuer, p.clientID, pend.nonce, clockLeeway, time.Now())
	if err != nil {
		http.Error(w, "ID 토큰 검증 실패: "+err.Error(), 400)
		return
	}

	s := &rpSession{
		ID: oidcclient.RandomURLSafe(24), User: claims.Sub, Sid: claims.Sid,
		IDToken: tok.IDToken, LoggedAt: time.Now(),
	}
	p.mu.Lock()
	p.sess[s.ID] = s
	if s.Sid != "" {
		p.bySID[s.Sid] = s.ID // so a logout token can find this session later
	}
	p.mu.Unlock()

	p.note("로그인. IdP 세션 sid=%s", short(s.Sid))
	http.SetCookie(w, &http.Cookie{
		Name: p.cookieName(), Value: s.ID, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ------------------------------------------------------------------ logout

// logoutLocal is what most applications call "logout": drop our own session
// and nothing else.
//
// It looks like it worked - the app shows you as logged out. But the IdP still
// has a live SSO session, so pressing login again silently signs you straight
// back in with no password. That is the bug this chapter exists for.
func (p *rp) logoutLocal(w http.ResponseWriter, r *http.Request) {
	p.dropSession(r)
	p.clearCookie(w)
	p.note("로컬 로그아웃. 우리 세션만 지웠다. IdP 세션은 그대로다")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logoutRPInitiated sends the browser to the IdP to end the SSO session too.
//
// id_token_hint says which session to end and proves we may ask. The IdP ends
// its session, then notifies every other RP in that session out of band, then
// sends the browser back to post_logout_redirect_uri.
func (p *rp) logoutRPInitiated(w http.ResponseWriter, r *http.Request) {
	s := p.session(r)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u, err := oidcclient.EndSessionURL(p.disc, s.IDToken, p.base+"/post-logout", oidcclient.RandomURLSafe(12))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p.dropSession(r)
	p.clearCookie(w)
	p.note("RP-Initiated 로그아웃. IdP의 end_session_endpoint로 보낸다")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *rp) postLogout(w http.ResponseWriter, r *http.Request) {
	p.note("IdP가 로그아웃을 마치고 돌려보냈다")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// backchannelLogout receives the IdP's server-to-server logout notification.
//
// This is how an RP learns that a session it did not end is over. No browser
// is involved, so it works even when third-party cookies are blocked - which
// is exactly why front-channel (iframe) logout has been failing in modern
// browsers and this replaced it.
func (p *rp) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST만 받는다", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	form, _ := url.ParseQuery(string(body))
	raw := form.Get("logout_token")
	if raw == "" {
		http.Error(w, "logout_token 없음", 400)
		return
	}

	claims, err := p.validateLogoutToken(raw)
	if err != nil {
		p.note("back-channel 로그아웃 거부: %v", err)
		http.Error(w, err.Error(), 400)
		return
	}

	p.mu.Lock()
	ourID, ok := p.bySID[claims.Sid]
	if ok {
		delete(p.sess, ourID)
		delete(p.bySID, claims.Sid)
	}
	p.mu.Unlock()

	if ok {
		p.note("back-channel 로그아웃 수신. sid=%s 세션을 지웠다 (브라우저 없이)", short(claims.Sid))
	} else {
		p.note("back-channel 로그아웃 수신했지만 sid=%s 에 해당하는 세션이 없다", short(claims.Sid))
	}
	w.WriteHeader(http.StatusOK)
}

// logoutClaims is the logout token payload (OIDC Back-Channel Logout 1.0 §2.4).
type logoutClaims struct {
	Iss    string              `json:"iss"`
	Aud    oidcclient.Audience `json:"aud"`
	Iat    int64               `json:"iat"`
	Jti    string              `json:"jti"`
	Sid    string              `json:"sid"`
	Sub    string              `json:"sub"`
	Events map[string]any      `json:"events"`
	Nonce  string              `json:"nonce"`
}

// validateLogoutToken checks a logout token.
//
// It looks like an ID token but the rules differ in two ways that matter:
//   - it MUST carry the back-channel logout event claim, which is what stops an
//     ID token from being replayed here as a logout command
//   - it MUST NOT have a nonce, for the same reason in reverse
//
// The signature is still not verified - that needs JWKS, same as chapter 02.
func (p *rp) validateLogoutToken(raw string) (*logoutClaims, error) {
	_, payload, _, err := oidcclient.SplitJWT(raw)
	if err != nil {
		return nil, err
	}
	var c logoutClaims
	if err := oidcclient.DecodeSegment(payload, &c); err != nil {
		return nil, err
	}
	if c.Iss != p.disc.Issuer {
		return nil, fmt.Errorf("iss 불일치: %q", c.Iss)
	}
	if !c.Aud.Contains(p.clientID) {
		return nil, fmt.Errorf("aud에 내 client_id가 없다: %v", []string(c.Aud))
	}
	if time.Since(time.Unix(c.Iat, 0)) > 5*time.Minute {
		return nil, fmt.Errorf("iat이 너무 오래됐다")
	}
	if _, ok := c.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, fmt.Errorf("back-channel logout 이벤트 클레임이 없다. ID 토큰을 대신 보낸 것일 수 있다")
	}
	if c.Nonce != "" {
		return nil, fmt.Errorf("logout token에는 nonce가 있으면 안 된다")
	}
	if c.Sid == "" && c.Sub == "" {
		return nil, fmt.Errorf("sid도 sub도 없다. 어느 세션인지 알 수 없다")
	}
	return &c, nil
}

// ------------------------------------------------------------------ helpers

func (p *rp) cookieName() string { return "rp_" + strings.ReplaceAll(p.clientID, "-", "_") }

func (p *rp) session(r *http.Request) *rpSession {
	c, err := r.Cookie(p.cookieName())
	if err != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sess[c.Value]
}

func (p *rp) dropSession(r *http.Request) {
	c, err := r.Cookie(p.cookieName())
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.sess[c.Value]; ok {
		delete(p.bySID, s.Sid)
	}
	delete(p.sess, c.Value)
}

func (p *rp) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: p.cookieName(), Value: "", Path: "/", MaxAge: -1})
}

func (p *rp) note(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	p.mu.Lock()
	p.log = append([]string{line}, p.log...)
	if len(p.log) > 8 {
		p.log = p.log[:8]
	}
	p.mu.Unlock()
	log.Printf("[%s] %s", p.name, fmt.Sprintf(format, args...))
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}

func (p *rp) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s := p.session(r)
	p.mu.Lock()
	events := append([]string(nil), p.log...)
	live := len(p.sess)
	p.mu.Unlock()

	data := map[string]any{
		"Name": p.name, "Peer": p.peer, "Live": live, "Events": events,
		"IdP": p.disc.Issuer,
	}
	if s != nil {
		data["Auth"] = true
		data["User"] = short(s.User)
		data["Sid"] = short(s.Sid)
		data["At"] = s.LoggedAt.Format("15:04:05")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, data)
}

var page = template.Must(template.New("p").Parse(`
<meta charset="utf-8">
<title>{{.Name}} · 로그아웃</title>
<style>
  :root { --fg:#1a1a1a; --muted:#6b6b6b; --bg:#fff; --panel:#f6f6f5; --line:#e4e4e2;
          --ok:#2b8a3e; --warn:#b4341c; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e6; --muted:#9a9a96; --bg:#161615; --panel:#232322; --line:#33332f;
            --ok:#69db7c; --warn:#e8845f; }
  }
  body { font: 15px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; max-width: 48rem;
         margin: 3rem auto; padding: 0 1.5rem; color: var(--fg); background: var(--bg); }
  h1 { font-size: 1.2rem; margin-bottom: .2rem; }
  h2 { font-size: .95rem; margin-top: 1.9rem; border-top: 1px solid var(--line); padding-top: 1rem; }
  p.sub { color: var(--muted); margin-top: 0; }
  table { border-collapse: collapse; width: 100%; }
  td { border-top: 1px solid var(--line); padding: .5rem .8rem .5rem 0; font-size: 14px; vertical-align: top; }
  td.m { white-space: nowrap; padding-right: 1.2rem; color: var(--muted); }
  code { background: var(--panel); padding: .1rem .35rem; border-radius: 3px; }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  button { font: inherit; padding: .45rem .9rem; cursor: pointer; border-radius: 4px;
           border: 1px solid var(--line); background: var(--panel); color: var(--fg); margin-right:.4rem; }
  form { display:inline; }
  ul { padding-left: 1.1rem; } li { margin:.25rem 0; font-size:13px; color:var(--muted); }
  a { color: inherit; }
</style>
<h1>{{.Name}}</h1>
<p class="sub">IdP: {{.IdP}}</p>

{{if .Auth}}
  <h2>로그인 상태</h2>
  <table>
    <tr><td class="m">sub</td><td>{{.User}}</td></tr>
    <tr><td class="m">IdP 세션 <code>sid</code></td><td>{{.Sid}} <span class="sub">— back-channel 통지가 이 값으로 온다</span></td></tr>
    <tr><td class="m">로그인 시각</td><td>{{.At}}</td></tr>
  </table>

  <h2>로그아웃 세 가지</h2>
  <form method="post" action="/logout-local"><button>1. 로컬만</button></form>
  <form method="post" action="/logout-rp-initiated"><button>2. RP-Initiated (IdP까지)</button></form>
  <p class="sub" style="margin-top:.8rem">
  <b>1번</b>을 누르고 다시 로그인해보라. 비밀번호를 안 묻는다 — IdP 세션이 살아 있어서다.<br>
  <b>2번</b>을 누르면 IdP 세션까지 끝난다. 다시 로그인하면 비밀번호를 묻는다.<br>
  그리고 2번을 누르면 <b>{{.Peer}} 의 세션도</b> back-channel 통지로 사라진다.</p>
{{else}}
  <h2>로그아웃 상태</h2>
  <form method="get" action="/login"><button>로그인</button></form>
  <p class="sub" style="margin-top:.8rem">비밀번호를 묻는지 보라.
  안 묻는다면 IdP 세션이 아직 살아 있다는 뜻이다.</p>
{{end}}

<h2>이 RP의 상태</h2>
<table>
  <tr><td class="m">살아있는 세션</td><td>{{.Live}}개</td></tr>
  <tr><td class="m">다른 RP</td><td><a href="{{.Peer}}">{{.Peer}}</a></td></tr>
</table>

<h2>일어난 일</h2>
{{if .Events}}<ul>{{range .Events}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p class="sub">아직 없음</p>{{end}}
`))
