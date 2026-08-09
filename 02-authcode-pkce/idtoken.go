package main

// Reading an ID token and checking its claims, by hand.
//
// What this file does NOT do: verify the signature. That needs JWKS and key
// selection by `kid`, which is chapter 03. Until then every check below runs
// on text an attacker could have written. `checks` records that fact so the
// gap shows up in the output instead of being quietly forgotten.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// audience is the `aud` claim.
//
// OIDC Core 1.0 §2 allows it to be a single string or an array of strings.
// A parser that handles only one shape works against one IdP and breaks
// against the next, which is how "it works in dev" happens.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud는 문자열이거나 문자열 배열이어야 한다: %w", err)
	}
	*a = many
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

type joseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type idClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      audience `json:"aud"`
	Azp      string   `json:"azp"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Sid      string   `json:"sid"`
}

// splitJWT returns the three segments of a compact JWS.
func splitJWT(token string) (header, payload, signature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("JWT는 점으로 나뉜 세 조각이어야 하는데 %d 조각이다", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

// decodeSegment decodes one base64url segment.
//
// RawURLEncoding, not StdEncoding: JWT uses the URL-safe alphabet (`-_`
// instead of `+/`) and drops the `=` padding, because the value has to survive
// being pasted into a URL.
func decodeSegment(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("base64url 디코딩 실패: %w", err)
	}
	return json.Unmarshal(raw, into)
}

// check is one validation we performed, kept so the result page can show the
// list. Seeing the checks enumerated is the point of this chapter: in 00 they
// happened inside Verify() and were invisible.
type check struct {
	Name     string
	Detail   string
	Passed   bool
	Deferred bool // not implemented yet, deferred to a later chapter
}

// validateIDToken parses an ID token and checks every claim we can check
// without a signature. It returns the checks performed even on failure, so the
// caller can show which one broke.
func validateIDToken(raw, issuer, clientID, wantNonce string, leeway time.Duration, now time.Time) (
	*joseHeader, *idClaims, []check, error,
) {
	headerSeg, payloadSeg, _, err := splitJWT(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	var h joseHeader
	if err := decodeSegment(headerSeg, &h); err != nil {
		return nil, nil, nil, fmt.Errorf("헤더: %w", err)
	}
	var c idClaims
	if err := decodeSegment(payloadSeg, &c); err != nil {
		return nil, nil, nil, fmt.Errorf("페이로드: %w", err)
	}

	var checks []check
	fail := func(name, detail string) ([]check, error) {
		checks = append(checks, check{Name: name, Detail: detail})
		return checks, fmt.Errorf("%s: %s", name, detail)
	}
	pass := func(name, detail string) {
		checks = append(checks, check{Name: name, Detail: detail, Passed: true})
	}

	// The signature is what makes every other claim worth reading. Recorded
	// first so it is impossible to look at this list and think we are done.
	checks = append(checks, check{
		Name:     "서명",
		Detail:   fmt.Sprintf("아직 검증하지 않는다 (alg=%s, kid=%s). 03에서 JWKS로 붙인다", h.Alg, h.Kid),
		Deferred: true,
	})

	if c.Iss != issuer {
		cs, err := fail("iss", fmt.Sprintf("%q 를 기대했는데 %q", issuer, c.Iss))
		return &h, &c, cs, err
	}
	pass("iss", "디스커버리 문서의 issuer와 일치")

	if !c.Aud.contains(clientID) {
		cs, err := fail("aud", fmt.Sprintf("%q 가 들어있어야 하는데 %v", clientID, []string(c.Aud)))
		return &h, &c, cs, err
	}
	pass("aud", fmt.Sprintf("내 client_id %q 가 들어있다", clientID))

	// With several audiences the token is readable by more than one party, so
	// `azp` has to name us explicitly. OIDC Core §3.1.3.7 step 4.
	if len(c.Aud) > 1 {
		if c.Azp != clientID {
			cs, err := fail("azp", fmt.Sprintf("aud가 여러 개인데 azp가 %q", c.Azp))
			return &h, &c, cs, err
		}
		pass("azp", "aud가 여러 개라서 azp까지 확인")
	}

	exp := time.Unix(c.Exp, 0)
	if now.After(exp.Add(leeway)) {
		cs, err := fail("exp", fmt.Sprintf("%s 에 만료됨 (%s 전)", exp.Format(time.TimeOnly), now.Sub(exp).Round(time.Second)))
		return &h, &c, cs, err
	}
	pass("exp", fmt.Sprintf("%s 까지 유효 (시계 오차 %s 허용)", exp.Format(time.TimeOnly), leeway))

	// Defence against replay. The library in chapter 00 did not do this one.
	if c.Nonce != wantNonce {
		cs, err := fail("nonce", "내가 보낸 값과 다르다. 리플레이된 토큰일 수 있다")
		return &h, &c, cs, err
	}
	pass("nonce", "내가 이번 요청에 보낸 값과 일치")

	return &h, &c, checks, nil
}
