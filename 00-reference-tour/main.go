// Command reference-tour turns the running IdP's own self-description into a
// top-down map of the whole subject.
//
// The idea (reference-first study): before building any mechanism from zero,
// look at one complete, real system - Keycloak - and read what it can do.
// Its discovery document already advertises most rows of notes/comparison.md
// as working features. This program fetches that document and annotates every
// capability with which comparison table it belongs to and which chapter will
// dissect it, writing 00-reference-tour/capability-map.md.
//
// No login, no OIDC library: just GET the discovery doc and the JWKS. The map
// is a reading index, not a flow. The flows are dissected in later chapters.
//
// Read 00-reference-tour/README.md first.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	issuer = flag.String("issuer", "http://localhost:8080/realms/demo", "OIDC issuer URL")
	out    = flag.String("out", "00-reference-tour/capability-map.md", "where to write the map")
)

// annotation ties one thing the IdP advertises to a place in the study map.
type annotation struct {
	field   string // discovery field name
	meaning string // what it is, in one line
	table   string // which comparison.md table / note
	chapter string // where it gets dissected, or its status
}

// The curated map. Order is the reading order, grouped by table. Every entry's
// `field` is read live from discovery so the map shows what THIS IdP actually
// offers, not what the spec allows. Fields present in discovery but absent here
// are listed at the end as "아직 지도에 없음" so gaps stay visible.
var annotations = []annotation{
	// --- 신뢰의 뿌리: 이 문서 자체와 서명 키 ---
	{"issuer", "이 IdP의 정체. 받은 토큰의 iss와 대조하는 기준", "뿌리", "00·02에서 확인"},
	{"jwks_uri", "서명 검증용 공개키 목록. 표 1 '신뢰의 뿌리'의 실물", "뿌리", "03에서 뜯음 (kid 선택)"},

	// --- 표 1: 로그인 방식 (어떤 흐름으로 누구인지 증명하나) ---
	{"authorization_endpoint", "브라우저를 보내는 곳. Authorization Code 흐름의 시작", "표1 OIDC", "완료 (00·02)"},
	{"token_endpoint", "code를 토큰으로 바꾸는 백채널", "표1 OIDC", "완료 (00·02)"},
	{"userinfo_endpoint", "액세스 토큰으로 사용자 정보를 받는 곳", "표1 OIDC", "완료 (00)"},
	{"code_challenge_methods_supported", "PKCE 방식. S256이 있어야 안전", "표1 OIDC", "완료 (02에서 직접 계산)"},
	{"grant_types_supported", "토큰을 받는 방법들. code / refresh / client_credentials / token-exchange ...", "표1·표4", "code=완료, token-exchange=lab"},
	{"acr_values_supported", "인증 강도 요청. 재인증·step-up의 재료", "AAL 노트", "05·MFA에서"},

	// --- 표 2: 토큰·요청 보호 (클라이언트가 자신을 증명하는 방법) ---
	{"token_endpoint_auth_methods_supported", "클라이언트 인증 방식. secret / private_key_jwt / mTLS", "표2", "secret=완료(02), private_key_jwt=01 후, mTLS=미착수"},
	{"dpop_signing_alg_values_supported", "DPoP 지원. 토큰을 클라이언트 키에 묶는다", "표2 DPoP", "미착수 (서버는 준비됨)"},
	{"introspection_endpoint", "불투명 토큰을 IdP에 물어 검증. 로컬 검증의 반대편", "표2·표1", "03에서 로컬 검증과 대조"},
	{"revocation_endpoint", "토큰을 즉시 무효화. bearer의 '취소 어려움'을 부분적으로 푼다", "표1 취소", "04에서"},

	// --- 표 3: SSO / 로그아웃 ---
	{"end_session_endpoint", "RP-Initiated Logout. 로그아웃의 시작점", "표3·로그아웃", "05에서 뜯음"},
	{"frontchannel_logout_supported", "iframe로 각 RP에 로그아웃 전파", "표3", "05"},
	{"backchannel_logout_supported", "IdP가 각 RP에 logout token을 POST", "표3", "05"},
	{"check_session_iframe", "세션이 살아있는지 브라우저에서 확인 (Session Management)", "표3 SSO", "05"},

	// --- 그 밖에 IdP가 할 수 있는 것 (지도의 가장자리) ---
	{"device_authorization_endpoint", "입력장치 없는 기기용 흐름 (TV 로그인)", "가장자리", "범위 밖"},
	{"backchannel_authentication_endpoint", "CIBA. 다른 기기로 승인받는 흐름", "가장자리", "범위 밖"},
	{"registration_endpoint", "클라이언트를 동적으로 등록 (RFC 7591)", "가장자리", "범위 밖"},
	{"pushed_authorization_request_endpoint", "인가 요청을 백채널로 미리 보냄 (PAR)", "가장자리", "범위 밖"},
}

type discoveryDoc map[string]any

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	doc, err := fetchJSON(ctx, strings.TrimSuffix(*issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		fmt.Fprintf(os.Stderr, "디스커버리 실패: %v\n\nKeycloak이 떠 있는지 확인: make kc-up\n", err)
		os.Exit(1)
	}

	var md strings.Builder
	writeMap(&md, doc)

	if err := os.WriteFile(*out, []byte(md.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "쓰기 실패: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("지도 생성: %s\n", *out)
	fmt.Printf("이 IdP가 광고하는 능력 %d개를 표에 매핑했다.\n", len(doc))
}

func writeMap(b *strings.Builder, doc discoveryDoc) {
	b.WriteString("# 능력 지도 — 완성품(Keycloak)이 할 수 있는 것\n\n")
	b.WriteString("이 파일은 `00-reference-tour`가 자동 생성한다. 직접 고치지 않는다.\n\n")
	b.WriteString("돌아가는 실제 IdP가 **자기 입으로** 광고하는 능력을, `notes/comparison.md`의 표에 매핑한 것이다.\n")
	b.WriteString("여기 있는 거의 모든 줄이 완성된 기능으로 이미 존재한다. 챕터는 그걸 하나씩 뜯는 작업이다.\n\n")
	b.WriteString("아래 값은 라이브러리 없이 디스커버리 문서 하나를 GET해서 읽은 것이다. 그 자체가 이 저장소의 첫 교훈이다 — 엔드포인트를 하드코딩하지 않고 한 번의 요청으로 받아온다.\n\n")
	b.WriteString("---\n\n")

	seen := map[string]bool{}
	groups := []string{"뿌리", "표1 OIDC", "표1·표4", "표2", "표2 DPoP", "표2·표1", "표1 취소", "표3·로그아웃", "표3", "표3 SSO", "AAL 노트", "가장자리"}
	titles := map[string]string{
		"뿌리":      "신뢰의 뿌리 — 무엇을 믿기로 하는가",
		"표1 OIDC": "표 1. 로그인 방식 (OIDC 흐름)",
		"표1·표4":   "표 1·4. 토큰을 받는 방법들",
		"표2":      "표 2. 클라이언트 인증 (토큰·요청 보호)",
		"표2 DPoP": "표 2. DPoP — 토큰을 키에 묶기",
		"표2·표1":   "표 1·2. 검증 방식",
		"표1 취소":   "표 1. 취소",
		"표3·로그아웃": "표 3 / 로그아웃",
		"표3":      "표 3. SSO 전파",
		"표3 SSO":  "표 3. SSO 세션",
		"AAL 노트":  "인증 강도 (NIST AAL)",
		"가장자리":    "지도의 가장자리 — 이 IdP는 하지만 이 저장소 범위 밖",
	}

	for _, g := range groups {
		rows := annotationsFor(g, doc, seen)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(b, "## %s\n\n", titles[g])
		b.WriteString("| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |\n|---|---|---|\n")
		for _, a := range rows {
			val := valueHint(doc[a.field])
			name := "`" + a.field + "`"
			if val != "" {
				name += "<br><small>" + val + "</small>"
			}
			fmt.Fprintf(b, "| %s | %s | %s |\n", name, a.meaning, a.chapter)
		}
		b.WriteString("\n")
	}

	// Honesty: anything the IdP advertises that we have not placed yet.
	var leftover []string
	for k := range doc {
		if !seen[k] && !strings.HasSuffix(k, "_supported") && !strings.HasSuffix(k, "_values_supported") {
			continue // suppress the long *_supported capability arrays from the leftover list
		}
		if !seen[k] {
			leftover = append(leftover, k)
		}
	}
	sort.Strings(leftover)
	if len(leftover) > 0 {
		b.WriteString("## 아직 지도에 없음\n\n")
		b.WriteString("이 IdP가 광고하지만 위에서 다루지 않은 것들이다. 대부분 세부 알고리즘 목록이나 확장 기능이다.\n")
		b.WriteString("파고들 만한 게 보이면 여기서 시작한다.\n\n")
		for _, k := range leftover {
			fmt.Fprintf(b, "- `%s`\n", k)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("## 그래서 다음\n\n")
	b.WriteString("이 지도의 각 줄이 `notes/comparison.md`의 한 칸이 된다.\n")
	b.WriteString("'어디서 뜯나' 열이 챕터 순서다. 완성품을 먼저 봤으니, 이제 하나씩 내려가며 손으로 재현하고 diff한다.\n")
}

// annotationsFor returns the annotations in group g whose field is present in
// the live discovery doc, marking each as seen.
func annotationsFor(g string, doc discoveryDoc, seen map[string]bool) []annotation {
	var out []annotation
	for _, a := range annotations {
		if a.table != g {
			continue
		}
		if _, ok := doc[a.field]; !ok {
			continue // this IdP does not advertise it; skip honestly
		}
		seen[a.field] = true
		out = append(out, a)
	}
	return out
}

// valueHint renders a short preview of a discovery value for context.
func valueHint(v any) string {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "http") {
			return "" // endpoints are self-explanatory; don't clutter
		}
		return truncate(t, 60)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		return truncate(strings.Join(parts, ", "), 90)
	case bool:
		return fmt.Sprintf("%v", t)
	default:
		return ""
	}
}

func fetchJSON(ctx context.Context, url string) (discoveryDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %s", url, res.Status)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
