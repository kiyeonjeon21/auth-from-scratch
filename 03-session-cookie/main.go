// Command session-cookie is the baseline login: no IdP, no tokens, no
// redirects. A form, a password check, a random id in a cookie, and a map on
// the server.
//
// Everything later in this repo exists because some property of this is not
// enough. Building it first is what makes those reasons visible.
//
// Two sites share one session store to show cookie-based SSO. They listen on
// different ports on purpose: cookies ignore the port, so one login covers
// both, which is both how shared-domain SSO works and a boundary people expect
// to exist and does not.
//
// Read 03-session-cookie/README.md before running.
package main

import (
	"context"
	"errors"
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kiyeonjeon/auth-from-scratch/internal/wiretrace"
)

var (
	listenA = flag.String("listen", "localhost:5557", "사이트 A 주소")
	listenB = flag.String("listen-b", "localhost:5558", "사이트 B 주소 (같은 세션 저장소 공유)")
	out     = flag.String("out", "03-session-cookie/trace.md", "트레이스 출력 경로")

	// Attack switches. Each disables exactly one defence so the chapter can
	// show what that defence was for. Off by default; never on outside this lab.
	unsafeFixation = flag.Bool("unsafe-no-regenerate", false,
		"로그인 시 세션 ID를 재발급하지 않는다 (session fixation 재현)")
	unsafeNoHTTPOnly = flag.Bool("unsafe-no-httponly", false,
		"HttpOnly를 끈다 (JS가 쿠키를 읽을 수 있게)")
)

const idleTimeout = 30 * time.Minute

// users is the credential store. Passwords are never kept in the clear, not
// even in a lab fixture: what is stored is a bcrypt hash, and login compares
// against that. bcrypt is deliberately slow and salts each hash, so a stolen
// table cannot be reversed by lookup. Argon2id is the current first choice;
// bcrypt is here because its self-contained "$2a$cost$salt+hash" format makes
// the moving parts visible in one string.
var users = map[string][]byte{}

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("alice"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	users["alice"] = h
}

type app struct {
	name    string
	store   *store
	rec     *wiretrace.Recorder
	cookies cookieOpts
	peer    string // the other site, for the SSO demo link

	traceOnce sync.Once
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	st := newStore(idleTimeout)
	rec := wiretrace.New()

	opts := defaultCookieOpts()
	if *unsafeNoHTTPOnly {
		opts.httpOnly = false
	}

	a := &app{name: "사이트 A", store: st, rec: rec, cookies: opts, peer: "http://" + *listenB}
	b := &app{name: "사이트 B", store: st, rec: rec, cookies: opts, peer: "http://" + *listenA}

	srvA := &http.Server{Addr: *listenA, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	srvB := &http.Server{Addr: *listenB, Handler: b.routes(), ReadHeaderTimeout: 5 * time.Second}

	log.Printf("사이트 A  http://%s", *listenA)
	log.Printf("사이트 B  http://%s   (같은 세션 저장소를 공유)", *listenB)
	log.Printf("계정      alice / alice")
	if *unsafeFixation {
		log.Printf("\n  [unsafe] 로그인 시 세션 ID를 재발급하지 않는다. session fixation에 취약하다.")
	}
	if *unsafeNoHTTPOnly {
		log.Printf("  [unsafe] HttpOnly 꺼짐. document.cookie로 세션 ID가 읽힌다.")
	}
	log.Printf("\n백채널 호출은 한 번도 없다. IdP가 없기 때문이다.\n")

	go serve(srvB)
	go serve(srvA)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srvA.Shutdown(ctx)
	_ = srvB.Shutdown(ctx)
	log.Println("\n종료")
}

func serve(s *http.Server) {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if errors.Is(err, syscall.EADDRINUSE) {
			log.Fatalf("%s 를 이미 누가 쓰고 있다. 다른 챕터 앱이 떠 있으면 끄고 다시 실행한다.", s.Addr)
		}
		log.Fatal(err)
	}
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc("/logout", a.logout)
	return mux
}

// home shows the session, logged in or not.
//
// An anonymous visitor also gets a session. That is what makes the fixation
// question real: a session id exists before anyone has proven anything, so the
// id that ends up authenticated had better not be the same one.
func (a *app) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.rec.Front(a.name+": 홈 방문", r.Method, absURL(r))

	s, ok := a.store.get(cookieID(r))
	if !ok {
		s = a.store.create("") // anonymous
		a.cookies.set(w, s.ID, idleTimeout)
	}
	a.render(w, r, s, "")
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.rec.Front(a.name+": 로그인 POST", r.Method, absURL(r))

	username := r.FormValue("username")
	hash, known := users[username]

	// Compare against the hash, and do it even when the user does not exist,
	// using a dummy hash. Returning early for an unknown user makes login time
	// leak whether an account exists.
	if !known {
		hash = users["alice"] // any valid hash; the compare below will fail
	}
	err := bcrypt.CompareHashAndPassword(hash, []byte(r.FormValue("password")))
	if !known || err != nil {
		old, _ := a.store.get(cookieID(r))
		a.render(w, r, old, "아이디 또는 비밀번호가 올바르지 않습니다")
		return
	}

	oldID := cookieID(r)

	// The defence this chapter is built around.
	//
	// The pre-login session id may have been chosen by an attacker and planted
	// in the victim's browser. Authenticating it in place hands the attacker a
	// logged-in session. Destroying it and issuing a fresh id is the fix, and
	// it is required at every privilege change, not just login.
	var s *session
	if *unsafeFixation {
		s, _ = a.store.get(oldID)
		if s == nil {
			s = a.store.create("")
		}
		s.Username = username
		s.AuthenticatedAt = time.Now()
	} else {
		a.store.destroy(oldID)
		s = a.store.create(username)
	}
	a.cookies.set(w, s.ID, idleTimeout)

	a.rec.Notes(a.name+": 로그인 처리", url.Values{
		"비밀번호 검증":    {"bcrypt 해시와 대조. 평문은 저장하지 않는다"},
		"세션 ID 재발급":  {regenNote(oldID, s.ID)},
		"브라우저가 받는 것": {"세션 ID 하나뿐. 사용자 정보는 서버에 남는다"},
		"백채널 호출":     {"없음. IdP가 없다"},
	})
	a.writeTrace()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func regenNote(oldID, newID string) string {
	if oldID == "" {
		return "로그인 전 세션이 없었다 (새로 발급)"
	}
	if oldID == newID {
		return "**재발급하지 않았다.** session fixation에 취약한 상태다"
	}
	return "이전 ID를 폐기하고 새 ID를 발급했다 (fixation 방어)"
}

// logout destroys the server-side session. This is the thing a self-contained
// token cannot do: after this line the session is gone everywhere at once.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	a.rec.Front(a.name+": 로그아웃", r.Method, absURL(r))
	a.store.destroy(cookieID(r))
	clearCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) writeTrace() {
	a.traceOnce.Do(func() {
		a.rec.Notes("이 챕터의 특징", url.Values{
			"상태 위치":  {"서버의 map. 브라우저는 의미 없는 ID만 들고 있다"},
			"백채널 호출": {"0회. OIDC(00·02)는 3회였다. IdP가 없으니 서버끼리 오갈 일이 없다"},
			"취소":     {"store.destroy 한 줄. 즉시, 전역으로 무효화된다"},
			"SSO":    {"쿠키는 포트를 구분하지 않는다. 5557에서 로그인하면 5558도 로그인 상태다"},
		})
		if err := a.rec.WriteMarkdown(*out, "03 · 세션 + 쿠키 (기준선)"); err != nil {
			log.Printf("트레이스 쓰기 실패: %v", err)
			return
		}
		log.Printf("트레이스 기록: %s", *out)
	})
}

func absURL(r *http.Request) *url.URL {
	return &url.URL{Scheme: "http", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
}

func (a *app) render(w http.ResponseWriter, r *http.Request, s *session, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{
		"Site":      a.name,
		"Peer":      a.peer,
		"Err":       errMsg,
		"Sessions":  a.store.count(),
		"HttpOnly":  a.cookies.httpOnly,
		"SameSite":  "Lax",
		"Regen":     !*unsafeFixation,
		"CookieRaw": rawCookieHeader(r),
	}
	if s != nil {
		data["SID"] = short(s.ID)
		data["Auth"] = s.authenticated()
		data["User"] = s.Username
		data["Since"] = s.CreatedAt.Format("15:04:05")
		if s.authenticated() {
			data["AuthAt"] = s.AuthenticatedAt.Format("15:04:05")
		}
	}
	_ = page.Execute(w, data)
}

// rawCookieHeader shows every cookie the browser attached, which makes the
// port-independence of cookies visible: Keycloak's cookies from :8080 show up
// here on :5557 too.
func rawCookieHeader(r *http.Request) string {
	names := make([]string, 0, 4)
	for _, c := range r.Cookies() {
		names = append(names, c.Name)
	}
	if len(names) == 0 {
		return "(없음)"
	}
	return strings.Join(names, ", ")
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

var page = template.Must(template.New("p").Parse(`
<meta charset="utf-8">
<title>{{.Site}} · 세션 + 쿠키</title>
<style>
  :root { --fg:#1a1a1a; --muted:#6b6b6b; --bg:#fff; --panel:#f6f6f5; --line:#e4e4e2;
          --ok:#2b8a3e; --warn:#b4341c; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e6; --muted:#9a9a96; --bg:#161615; --panel:#232322; --line:#33332f;
            --ok:#69db7c; --warn:#e8845f; }
  }
  body { font: 15px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; max-width: 46rem;
         margin: 3rem auto; padding: 0 1.5rem; color: var(--fg); background: var(--bg); }
  h1 { font-size: 1.2rem; margin-bottom: .2rem; }
  h2 { font-size: .95rem; margin-top: 2rem; border-top: 1px solid var(--line); padding-top: 1rem; }
  p.sub { color: var(--muted); margin-top: 0; }
  table { border-collapse: collapse; width: 100%; }
  td { border-top: 1px solid var(--line); padding: .55rem .8rem .55rem 0; font-size: 14px;
       vertical-align: top; }
  td.m { white-space: nowrap; padding-right: 1.4rem; color: var(--muted); }
  code { background: var(--panel); padding: .1rem .35rem; border-radius: 3px; }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  input { font: inherit; padding: .4rem .5rem; background: var(--bg); color: var(--fg);
          border: 1px solid var(--line); border-radius: 4px; }
  button { font: inherit; padding: .4rem 1rem; cursor: pointer; border-radius: 4px;
           border: 1px solid var(--line); background: var(--panel); color: var(--fg); }
  a { color: inherit; }
</style>
<h1>{{.Site}}</h1>
<p class="sub">IdP 없음 · 토큰 없음 · 리다이렉트 없음</p>

{{if .Err}}<p class="warn">{{.Err}}</p>{{end}}

{{if .Auth}}
  <h2>로그인 상태</h2>
  <table>
    <tr><td class="m">사용자</td><td>{{.User}}</td></tr>
    <tr><td class="m">세션 ID</td><td><code>{{.SID}}</code> <span class="sub">— 브라우저가 가진 건 이게 전부다</span></td></tr>
    <tr><td class="m">세션 생성</td><td>{{.Since}}</td></tr>
    <tr><td class="m">인증 시각</td><td>{{.AuthAt}}</td></tr>
  </table>
  <form method="post" action="/logout"><button>로그아웃</button></form>
  <p class="sub">로그아웃은 서버 map에서 지운다. 즉시, 전역으로 끝난다.</p>
{{else}}
  <h2>로그인</h2>
  <p class="sub">익명 세션 ID: <code>{{.SID}}</code> — 로그인 후 이 값이 바뀌는지 보라</p>
  <form method="post" action="/login">
    <input name="username" placeholder="alice" autocomplete="off">
    <input name="password" type="password" placeholder="비밀번호">
    <button>로그인</button>
  </form>
{{end}}

<h2>지금 이 앱의 설정</h2>
<table>
  <tr><td class="m">상태 위치</td><td>서버 (map). 브라우저엔 ID만</td></tr>
  <tr><td class="m">백채널 호출</td><td>0회 — IdP가 없다</td></tr>
  <tr><td class="m">저장된 세션</td><td>{{.Sessions}}개</td></tr>
  <tr><td class="m">HttpOnly</td>
      <td>{{if .HttpOnly}}<span class="ok">켜짐</span> — JS가 못 읽는다{{else}}<span class="warn">꺼짐</span> — <code>document.cookie</code>로 읽힌다{{end}}</td></tr>
  <tr><td class="m">SameSite</td><td>{{.SameSite}}</td></tr>
  <tr><td class="m">로그인 시 ID 재발급</td>
      <td>{{if .Regen}}<span class="ok">함</span> — fixation 방어{{else}}<span class="warn">안 함</span> — fixation에 취약{{end}}</td></tr>
  <tr><td class="m">브라우저가 보낸 쿠키</td><td><code>{{.CookieRaw}}</code></td></tr>
</table>

<h2>SSO 확인</h2>
<p><a href="{{.Peer}}">{{.Peer}}</a> 를 열어보라.</p>
<p class="sub">포트가 다른데도 로그인 상태가 그대로다.
<b>쿠키는 포트를 구분하지 않는다.</b> 이게 공유 도메인 쿠키 SSO의 원리이자,
사람들이 있을 거라 착각하는 경계다. 위 "브라우저가 보낸 쿠키"에 Keycloak(:8080)의 쿠키가
섞여 있다면 같은 이유다.</p>
`))
