// Package wiretrace records every HTTP exchange of an OAuth/OIDC login and
// renders it as annotated Markdown.
//
// It exists because the whole point of chapter 00 is to see what a library
// does on the wire before reimplementing it by hand. Later chapters reuse it
// to diff their own traffic against the chapter 00 baseline.
//
// Two channels are recorded separately, because the split is the single most
// important structural fact about OAuth:
//
//   - front channel: anything routed through the user's browser (redirects,
//     query strings). Visible to the user, to extensions, to the referer
//     header, to the browser history.
//   - back channel: direct server-to-server calls. The only place a secret is
//     allowed to appear.
package wiretrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ChannelFront = "front"
	ChannelBack  = "back"
	ChannelNote  = "note"
)

// Exchange is one recorded HTTP round trip, one front-channel hop, or one
// annotation block (ChannelNote) such as decoded token claims.
type Exchange struct {
	Seq     int
	At      time.Duration
	Channel string
	Note    string

	Method string
	URL    *url.URL

	ReqHeader http.Header
	ReqBody   string

	Status    string
	ResHeader http.Header
	ResBody   string

	// Detail holds a standalone table for ChannelNote entries.
	Detail url.Values
	// Lookup decides which glossary annotates Detail, if any.
	Lookup lookupMode

	// Catalog marks a response that is a capability listing rather than a
	// protocol message. Discovery and JWKS have dozens of fields that answer
	// "what can this server do", not "why is this value in this message", so
	// annotating them per field buries the trace in noise.
	Catalog bool
}

type lookupMode int

const (
	lookupNone lookupMode = iota
	lookupClaim
	lookupJOSEHeader
)

func (m lookupMode) describe(name string) string {
	switch m {
	case lookupClaim:
		return describe(name)
	case lookupJOSEHeader:
		return describeHeader(name)
	default:
		return ""
	}
}

// Finding is something in this particular run that should bother the reader.
//
// A trace is a uniform wall of tables, and a reader who does not already know
// what matters will not find it. Findings are computed from the captured data,
// never hardcoded, so they cannot claim something the run does not show.
type Finding struct {
	Headline string
	// Plain explains the finding without assuming any protocol vocabulary.
	// It comes first everywhere, because a reader who cannot get past the
	// first sentence never reaches the accurate one.
	Plain    string
	Body     string
	Evidence string
}

// Recorder collects exchanges in the order they happen.
type Recorder struct {
	mu       sync.Mutex
	start    time.Time
	items    []Exchange
	findings []Finding

	// Redact replaces client secrets and passwords with a placeholder.
	// Tokens are always kept: reading them is the point of the exercise.
	Redact bool
}

// Find records a finding to surface at the top of the trace.
func (r *Recorder) Find(headline, plain, body, evidence string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, Finding{headline, plain, body, evidence})
}

// Findings returns what was found, for callers that also want to display it.
func (r *Recorder) Findings() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Finding(nil), r.findings...)
}

func New() *Recorder {
	return &Recorder{start: time.Now(), Redact: true}
}

func (r *Recorder) add(e Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Seq = len(r.items) + 1
	e.At = time.Since(r.start).Round(time.Millisecond)
	r.items = append(r.items, e)
}

// Front records a front-channel hop: a redirect this app issues to the
// browser, or a request the browser makes back to this app.
func (r *Recorder) Front(note, method string, u *url.URL) {
	r.add(Exchange{Channel: ChannelFront, Note: note, Method: method, URL: u})
}

// Claims records decoded token claims, annotated from the claim glossary.
func (r *Recorder) Claims(note string, values url.Values) {
	r.add(Exchange{Channel: ChannelNote, Note: note, Detail: values, Lookup: lookupClaim})
}

// Header records a decoded JOSE header, annotated from the header glossary.
func (r *Recorder) Header(note string, values url.Values) {
	r.add(Exchange{Channel: ChannelNote, Note: note, Detail: values, Lookup: lookupJOSEHeader})
}

// Notes records a plain commentary block. The values are already prose, so no
// glossary is consulted and no TODO markers are emitted.
func (r *Recorder) Notes(note string, values url.Values) {
	r.add(Exchange{Channel: ChannelNote, Note: note, Detail: values, Lookup: lookupNone})
}

// Transport wraps next so that every request through it is recorded as a
// back-channel exchange. Pass the resulting client to go-oidc and oauth2 via
// oidc.ClientContext / oauth2.HTTPClient.
func (r *Recorder) Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &tracingTransport{rec: r, next: next}
}

// Client returns an *http.Client whose traffic is recorded.
func (r *Recorder) Client() *http.Client {
	return &http.Client{Transport: r.Transport(nil), Timeout: 15 * time.Second}
}

type tracingTransport struct {
	rec  *Recorder
	next http.RoundTripper
}

func (t *tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	note, catalog := backChannelNote(req.URL)
	e := Exchange{
		Channel:   ChannelBack,
		Note:      note,
		Catalog:   catalog,
		Method:    req.Method,
		URL:       req.URL,
		ReqHeader: req.Header.Clone(),
	}

	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		e.ReqBody = string(body)
	}

	res, err := t.next.RoundTrip(req)
	if err != nil {
		e.Status = "transport error: " + err.Error()
		t.rec.add(e)
		return nil, err
	}

	body, readErr := io.ReadAll(res.Body)
	res.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	res.Body = io.NopCloser(bytes.NewReader(body))

	e.Status = res.Status
	e.ResHeader = res.Header.Clone()
	e.ResBody = string(body)
	t.rec.add(e)
	return res, nil
}

// backChannelNote labels well-known endpoints so the trace reads as a story
// rather than a list of URLs. The second return marks capability catalogs,
// which are rendered as raw JSON instead of a per-field annotation table.
func backChannelNote(u *url.URL) (note string, catalog bool) {
	switch {
	case strings.Contains(u.Path, "/.well-known/"):
		return "디스커버리 문서 가져오기", true
	case strings.HasSuffix(u.Path, "/certs"), strings.Contains(u.Path, "jwks"):
		return "JWKS 가져오기 (ID 토큰 서명 검증용 공개키)", true
	case strings.HasSuffix(u.Path, "/token"):
		return "토큰 엔드포인트. code를 토큰으로 교환", false
	case strings.HasSuffix(u.Path, "/userinfo"):
		return "UserInfo 엔드포인트", false
	case strings.Contains(u.Path, "introspect"):
		return "Token introspection", false
	case strings.Contains(u.Path, "logout"):
		return "로그아웃", false
	default:
		return "", false
	}
}

// ---------------------------------------------------------------- rendering

// WriteMarkdown renders the recorded exchanges to path.
func (r *Recorder) WriteMarkdown(path, title string) error {
	r.mu.Lock()
	items := append([]Exchange(nil), r.items...)
	findings := append([]Finding(nil), r.findings...)
	r.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	b.WriteString("이 파일은 챕터 코드가 자동 생성한다. 직접 고치지 않는다.\n")
	b.WriteString("막히는 값은 챕터 README의 `생각해볼 질문`에서 짚는다. 답은 이 트레이스와 코드에 있다.\n\n")
	b.WriteString("`**TODO**`로 표시된 값은 용어집에 없는 것이다. 그게 바로 파고들 지점이다.\n\n")

	if len(findings) > 0 {
		b.WriteString("## 먼저 볼 것\n\n")
		b.WriteString("아래는 **이번 실행의 실제 데이터에서 계산된 것**이다. 미리 써둔 문장이 아니다.\n")
		b.WriteString("트레이스 전체를 읽기 전에 이것부터 확인한다.\n\n")
		for i, f := range findings {
			fmt.Fprintf(&b, "### %d. %s\n\n", i+1, f.Headline)
			if f.Plain != "" {
				fmt.Fprintf(&b, "%s\n\n", f.Plain)
				b.WriteString("<details><summary>정확한 용어로</summary>\n\n")
			}
			fmt.Fprintf(&b, "%s\n\n", f.Body)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "```\n%s\n```\n\n", f.Evidence)
			}
			if f.Plain != "" {
				b.WriteString("</details>\n\n")
			}
		}
		b.WriteString("---\n\n")
	}

	b.WriteString("## 한눈에 보기\n\n")
	b.WriteString("| # | +시간 | 채널 | 무엇 |\n|---|---|---|---|\n")
	for _, e := range items {
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", e.Seq, e.At, channelLabel(e.Channel), headline(e))
	}
	b.WriteString("\n프론트채널은 브라우저를 거쳐 간다. 사용자도, 확장 프로그램도, 히스토리도 볼 수 있다.\n")
	b.WriteString("백채널은 서버끼리만 오간다. 시크릿이 나와도 되는 유일한 자리다.\n\n")
	b.WriteString("---\n\n")

	for _, e := range items {
		r.renderExchange(&b, e)
	}

	b.WriteString("## 여기에 안 잡히는 구간\n\n")
	b.WriteString("인가 엔드포인트로 리다이렉트한 뒤 콜백이 돌아올 때까지, 브라우저와 IdP 사이에서\n")
	b.WriteString("로그인 폼 렌더링과 자격증명 POST가 일어난다. 그건 이 앱을 거치지 않으므로 여기 안 남는다.\n")
	b.WriteString("보려면 브라우저 개발자도구 네트워크 탭에서 **Preserve log**를 켜고 다시 로그인한다.\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func channelLabel(c string) string {
	switch c {
	case ChannelFront:
		return "front (브라우저 경유)"
	case ChannelNote:
		return "해설"
	default:
		return "back (서버 간)"
	}
}

// headline is the short label used in the summary table and section heading.
func headline(e Exchange) string {
	if e.Note != "" {
		return e.Note
	}
	if e.URL != nil {
		return e.URL.Path
	}
	return "(제목 없음)"
}

func (r *Recorder) renderExchange(b *strings.Builder, e Exchange) {
	fmt.Fprintf(b, "## %d. [%s] %s\n\n", e.Seq, channelLabel(e.Channel), headline(e))

	if e.Channel == ChannelNote {
		r.renderParams(b, e.Detail, e.Lookup)
		b.WriteString("---\n\n")
		return
	}

	fmt.Fprintf(b, "```\n%s %s\n```\n\n", e.Method, r.redact(stripQuery(e.URL)))

	if q := e.URL.Query(); len(q) > 0 {
		b.WriteString("**쿼리 파라미터**\n\n")
		r.renderParams(b, q, lookupClaim)
	}

	if h := interestingHeaders(e.ReqHeader); len(h) > 0 {
		b.WriteString("**요청 헤더**\n\n")
		for _, k := range sortedKeys(h) {
			fmt.Fprintf(b, "- `%s: %s`\n", k, r.redact(strings.Join(h[k], ", ")))
		}
		b.WriteString("\n")
	}

	if e.ReqBody != "" {
		b.WriteString("**요청 본문**\n\n")
		r.renderBody(b, e.ReqHeader.Get("Content-Type"), e.ReqBody, false)
	}

	if e.Status != "" {
		fmt.Fprintf(b, "**응답** `%s`\n\n", e.Status)
	}
	if e.ResBody != "" {
		if e.Catalog {
			b.WriteString("서버가 무엇을 할 수 있는지의 목록이다. 메시지가 아니라 카탈로그라 항목별 주석을 붙이지 않는다.\n")
			b.WriteString("여기서 봐야 할 것은 개별 필드가 아니라, **이 문서 하나가 하드코딩을 몇 개나 대체했는가** 다.\n\n")
		}
		r.renderBody(b, e.ResHeader.Get("Content-Type"), e.ResBody, e.Catalog)
	}
	b.WriteString("---\n\n")
}

func (r *Recorder) renderParams(b *strings.Builder, values url.Values, mode lookupMode) {
	if mode == lookupNone {
		b.WriteString("| | |\n|---|---|\n")
		for _, k := range sortedKeys(values) {
			fmt.Fprintf(b, "| `%s` | %s |\n", k, strings.Join(values[k], ", "))
		}
		b.WriteString("\n")
		return
	}
	b.WriteString("| 이름 | 값 | 왜 있나 |\n|---|---|---|\n")
	for _, k := range sortedKeys(values) {
		v := strings.Join(values[k], ", ")
		fmt.Fprintf(b, "| `%s` | `%s` | %s |\n", k, r.redact(truncate(v, 110)), mode.describe(k))
	}
	b.WriteString("\n")
}

// renderBody writes a request or response body. Table-worthy bodies get the
// annotation table; catalogs get raw JSON only.
func (r *Recorder) renderBody(b *strings.Builder, contentType, body string, catalog bool) {
	switch {
	case strings.Contains(contentType, "x-www-form-urlencoded"):
		if v, err := url.ParseQuery(body); err == nil {
			r.renderParams(b, v, lookupClaim)
			return
		}
	case strings.Contains(contentType, "json"):
		var pretty bytes.Buffer
		if json.Indent(&pretty, []byte(body), "", "  ") == nil {
			var m map[string]any
			if !catalog && json.Unmarshal([]byte(body), &m) == nil {
				vals := url.Values{}
				for k, v := range m {
					vals.Set(k, summarize(v))
				}
				r.renderParams(b, vals, lookupClaim)
			}
			fmt.Fprintf(b, "<details><summary>원본 JSON</summary>\n\n```json\n%s\n```\n\n</details>\n\n",
				r.redact(truncate(pretty.String(), 6000)))
			return
		}
	}
	fmt.Fprintf(b, "```\n%s\n```\n\n", r.redact(truncate(body, 2000)))
}

// summarize renders a JSON value as a single line. Truncation is left to the
// caller so a value is never cut twice.
func summarize(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case nil:
		return "null"
	default:
		out, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(out)
	}
}

// interestingHeaders drops transport noise so the table stays readable.
func interestingHeaders(h http.Header) http.Header {
	keep := map[string]bool{
		"Authorization": true, "Content-Type": true, "Dpop": true,
		"Location": true, "Cookie": true, "Referer": true,
	}
	out := http.Header{}
	for k, v := range h {
		if keep[http.CanonicalHeaderKey(k)] {
			out[http.CanonicalHeaderKey(k)] = v
		}
	}
	return out
}

var secretParams = []string{"client_secret", "password", "client_assertion"}

func (r *Recorder) redact(s string) string {
	if !r.Redact {
		return s
	}
	for _, p := range secretParams {
		s = replaceParam(s, p)
	}
	// Basic auth carries base64(client_id:client_secret).
	if i := strings.Index(s, "Basic "); i >= 0 {
		s = s[:i] + "Basic <base64(client_id:client_secret) 생략>"
	}
	return s
}

// replaceParam blanks the value of param wherever it appears as key=value.
func replaceParam(s, param string) string {
	var out strings.Builder
	rest := s
	for {
		i := strings.Index(rest, param+"=")
		if i < 0 {
			out.WriteString(rest)
			return out.String()
		}
		out.WriteString(rest[:i+len(param)+1])
		out.WriteString("<생략>")
		rest = rest[i+len(param)+1:]
		if j := strings.IndexAny(rest, "&\n\", "); j >= 0 {
			rest = rest[j:]
		} else {
			return out.String()
		}
	}
}

func stripQuery(u *url.URL) string {
	c := *u
	c.RawQuery = ""
	return c.String()
}

// truncate cuts on rune boundaries. Slicing bytes splits Korean mid-character
// and leaves mojibake in the table.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + fmt.Sprintf("… (전체 %d자 중 %d자)", len(runes), n)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
