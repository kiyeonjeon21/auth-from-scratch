// Package oidcclient is the OIDC client this repo wrote by hand in chapter 02.
//
// It is not a library dependency: every line here was written in
// 02-authcode-pkce and moved out when a second chapter needed it. Standard
// library and crypto primitives only. Read it as chapter 02's source that
// happens to live in a shared place.
package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kiyeonjeon/auth-from-scratch/internal/jwks"
)

// ---------------------------------------------------------------- discovery

// Discovery is the subset of provider metadata this client actually uses.
//
// The document has ~50 fields. Declaring only what we consume is deliberate:
// every field here is one the code below reads.
type Discovery struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	EndSessionEndpoint       string   `json:"end_session_endpoint"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// FetchDiscovery loads and checks the provider metadata.
func FetchDiscovery(ctx context.Context, hc *http.Client, issuer string) (*Discovery, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("디스커버리 %s: HTTP %s", u, res.Status)
	}

	var d Discovery
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("디스커버리 문서 파싱 실패: %w", err)
	}

	// The check that is easy to skip and expensive to skip.
	//
	// The document is fetched from a URL derived from the issuer, but its
	// contents claim an issuer of their own. If those disagree, someone is
	// pointing us at endpoints that belong to a different provider while we
	// keep validating tokens against the issuer we thought we asked for.
	if d.Issuer != issuer {
		return nil, fmt.Errorf(
			"issuer 불일치: 요청한 곳은 %q 인데 문서는 %q 라고 주장한다", issuer, d.Issuer)
	}

	// PKCE without S256 is not PKCE. `plain` sends the verifier itself as the
	// challenge, so the front channel carries the secret it was meant to hide.
	if !slices.Contains(d.CodeChallengeMethods, "S256") {
		return nil, fmt.Errorf("이 IdP는 S256을 지원하지 않는다: %v", d.CodeChallengeMethods)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("필수 엔드포인트가 비어 있다")
	}
	return &d, nil
}

// --------------------------------------------------------------------- PKCE

// NewVerifier returns a fresh `code_verifier`.
//
// RFC 7636 §4.1 wants 43-128 characters of high-entropy unreserved text.
// 32 random bytes base64url-encoded is exactly 43 characters. The length is
// not decoration: the challenge is public, so the only thing stopping an
// attacker from hashing candidates until one matches is the input space.
func NewVerifier() string { return RandomURLSafe(32) }

// ChallengeS256 derives the `code_challenge` from a verifier.
//
// BASE64URL(SHA256(ASCII(verifier))), unpadded. This is the one-way step: the
// challenge travels the front channel, the verifier does not.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomURLSafe returns n cryptographically random bytes as base64url text.
func RandomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means we must not continue.
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// -------------------------------------------------------- authorize request

// AuthorizeParams is one authorization request.
//
// Extra carries optional parameters such as `prompt` or `max_age`. They live
// here rather than as fields because they are the exception, and because the
// logout chapter needs to add them without every other caller caring.
type AuthorizeParams struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Challenge   string
	Extra       url.Values
}

// AuthorizeURL builds the front-channel request that sends the browser to the IdP.
//
// Every parameter here ends up in the address bar, so nothing secret may be
// added. `code_challenge` is safe precisely because it is a hash.
func AuthorizeURL(d *Discovery, p AuthorizeParams) (*url.URL, error) {
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ClientID},
		"redirect_uri":          {p.RedirectURI},
		"scope":                 {p.Scope},
		"state":                 {p.State},
		"nonce":                 {p.Nonce},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range p.Extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u, nil
}

// ------------------------------------------------------------ token exchange

// ClientAuthMethod is how the client proves it is itself at the token endpoint.
type ClientAuthMethod string

const (
	// AuthBasic puts base64(client_id:client_secret) in the Authorization
	// header. RFC 6749 §2.3.1 names this the preferred form.
	AuthBasic ClientAuthMethod = "client_secret_basic"
	// AuthPost puts client_id and client_secret in the form body. Same secret,
	// same channel; it differs only in which part of the request carries it,
	// which matters for what gets logged.
	AuthPost ClientAuthMethod = "client_secret_post"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type TokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e TokenError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// ExchangeParams is one token-endpoint call.
type ExchangeParams struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Code         string
	Verifier     string
	Auth         ClientAuthMethod
}

// ExchangeCode trades the authorization code for tokens over the back channel.
//
// This is the only request in the whole flow that may carry a secret, because
// it is the only one the browser never touches.
func ExchangeCode(ctx context.Context, hc *http.Client, d *Discovery, p ExchangeParams) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {p.Code},
		"redirect_uri": {p.RedirectURI},
		// Sent again even though the IdP already has it from the authorization
		// request. RFC 6749 §4.1.3 requires the two to match: it stops a client
		// from being talked into redeeming a code minted for another callback.
		"code_verifier": {p.Verifier},
	}
	if p.Auth == AuthPost {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", p.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.Auth == AuthBasic {
		// url.QueryEscape per RFC 6749 §2.3.1: the credentials are
		// form-urlencoded before base64, not used raw.
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}

	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		var te TokenError
		if json.Unmarshal(body, &te) == nil && te.Code != "" {
			return nil, te
		}
		return nil, fmt.Errorf("토큰 엔드포인트 HTTP %s: %s", res.Status, Truncate(string(body), 300))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("토큰 응답 파싱 실패: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("ID 토큰이 없다. scope에 openid가 빠졌을 때 이렇게 된다")
	}
	return &tr, nil
}

func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// ------------------------------------------------------------------ logout

// EndSessionURL builds the RP-Initiated Logout request (OIDC RP-Initiated
// Logout 1.0).
//
// This is the piece that separates "log out of my app" from "log out". Without
// it the IdP session survives and the next login needs no password.
//
// id_token_hint tells the IdP which session to end and proves we are entitled
// to ask; without it the IdP has to show a confirmation page instead.
func EndSessionURL(d *Discovery, idTokenHint, postLogoutRedirectURI, state string) (*url.URL, error) {
	if d.EndSessionEndpoint == "" {
		return nil, fmt.Errorf("이 IdP는 end_session_endpoint를 광고하지 않는다")
	}
	u, err := url.Parse(d.EndSessionEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u, nil
}

// --------------------------------------------------------------- ID token
//
// What this does NOT do: verify the signature. That needs JWKS and key
// selection by `kid`. Until then every check below runs on text an attacker
// could have written, and Checks records that so the gap stays visible.

// Audience is the `aud` claim.
//
// OIDC Core 1.0 §2 allows it to be a single string or an array of strings.
// A parser that handles only one shape works against one IdP and breaks
// against the next, which is how "it works in dev" happens.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud는 문자열이거나 문자열 배열이어야 한다: %w", err)
	}
	*a = many
	return nil
}

func (a Audience) Contains(s string) bool {
	return slices.Contains([]string(a), s)
}

type JOSEHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type IDClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      Audience `json:"aud"`
	Azp      string   `json:"azp"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Sid      string   `json:"sid"`
}

// SplitJWT returns the three segments of a compact JWS.
func SplitJWT(token string) (header, payload, signature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("JWT는 점으로 나뉜 세 조각이어야 하는데 %d 조각이다", len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

// DecodeSegment decodes one base64url segment.
//
// RawURLEncoding, not StdEncoding: JWT uses the URL-safe alphabet (`-_`
// instead of `+/`) and drops `=` padding, because the value has to survive
// being pasted into a URL.
func DecodeSegment(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("base64url 디코딩 실패: %w", err)
	}
	return json.Unmarshal(raw, into)
}

// Check is one validation we performed, kept so a chapter can show the list.
// Seeing the checks enumerated is the point: with a library they happen inside
// Verify() and are invisible.
type Check struct {
	Name     string
	Detail   string
	Passed   bool
	Deferred bool // not implemented yet, deferred to a later chapter
}

// SignatureVerifier checks a compact JWS against the issuer's public keys.
// internal/jwks implements it. Nil means "not wired yet", which the check list
// reports honestly rather than silently skipping.
type SignatureVerifier interface {
	Verify(ctx context.Context, token string) (*jwks.Header, error)
}

// Validator holds what every ID token from one issuer is checked against.
type Validator struct {
	Issuer   string
	ClientID string
	Leeway   time.Duration
	Keys     SignatureVerifier
}

// ValidateIDToken parses an ID token and checks it. It returns the checks
// performed even on failure, so the caller can show which one broke.
//
// The signature is checked FIRST. Every claim below it is only worth reading
// because the signature says the IdP wrote them; validating claims on an
// unverified token is theatre.
func (v Validator) ValidateIDToken(ctx context.Context, raw, wantNonce string, now time.Time) (
	*JOSEHeader, *IDClaims, []Check, error,
) {
	issuer, clientID, leeway := v.Issuer, v.ClientID, v.Leeway
	headerSeg, payloadSeg, _, err := SplitJWT(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	var h JOSEHeader
	if err := DecodeSegment(headerSeg, &h); err != nil {
		return nil, nil, nil, fmt.Errorf("헤더: %w", err)
	}
	var c IDClaims
	if err := DecodeSegment(payloadSeg, &c); err != nil {
		return nil, nil, nil, fmt.Errorf("페이로드: %w", err)
	}

	var checks []Check
	fail := func(name, detail string) ([]Check, error) {
		checks = append(checks, Check{Name: name, Detail: detail})
		return checks, fmt.Errorf("%s: %s", name, detail)
	}
	pass := func(name, detail string) {
		checks = append(checks, Check{Name: name, Detail: detail, Passed: true})
	}

	// The signature is what makes every other claim worth reading, so it runs
	// before any of them and a failure stops everything.
	if v.Keys == nil {
		checks = append(checks, Check{
			Name:     "서명",
			Detail:   fmt.Sprintf("검증기가 연결되지 않았다 (alg=%s, kid=%s)", h.Alg, h.Kid),
			Deferred: true,
		})
	} else if _, err := v.Keys.Verify(ctx, raw); err != nil {
		cs, ferr := fail("서명", err.Error())
		return &h, &c, cs, ferr
	} else {
		pass("서명", fmt.Sprintf("JWKS의 공개키로 검증됨 (alg=%s, kid=%s)", h.Alg, h.Kid))
	}

	if c.Iss != issuer {
		cs, err := fail("iss", fmt.Sprintf("%q 를 기대했는데 %q", issuer, c.Iss))
		return &h, &c, cs, err
	}
	pass("iss", "디스커버리 문서의 issuer와 일치")

	if !c.Aud.Contains(clientID) {
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
		cs, err := fail("exp", fmt.Sprintf("%s 에 만료됨 (%s 전)",
			exp.Format(time.TimeOnly), now.Sub(exp).Round(time.Second)))
		return &h, &c, cs, err
	}
	pass("exp", fmt.Sprintf("%s 까지 유효 (시계 오차 %s 허용)", exp.Format(time.TimeOnly), leeway))

	// Defence against replay. The library in chapter 00 did not do this one.
	if wantNonce != "" {
		if c.Nonce != wantNonce {
			cs, err := fail("nonce", "내가 보낸 값과 다르다. 리플레이된 토큰일 수 있다")
			return &h, &c, cs, err
		}
		pass("nonce", "내가 이번 요청에 보낸 값과 일치")
	}

	return &h, &c, checks, nil
}
