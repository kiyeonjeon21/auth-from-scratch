package main

// Everything go-oidc and x/oauth2 did for us in chapter 00, by hand.
// Standard library and crypto primitives only.

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
)

// ---------------------------------------------------------------- discovery

// discovery is the subset of provider metadata this client actually uses.
//
// The document has ~50 fields. Declaring only what we consume is deliberate:
// every field here is one the code below reads, so the struct doubles as the
// answer to "what did that one GET actually buy us".
type discovery struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	CodeChallengeMethods     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// fetchDiscovery loads and checks the provider metadata.
func fetchDiscovery(ctx context.Context, hc *http.Client, issuer string) (*discovery, error) {
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

	var d discovery
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

// newVerifier returns a fresh `code_verifier`.
//
// RFC 7636 §4.1 wants 43-128 characters of high-entropy unreserved text.
// 32 random bytes base64url-encoded is exactly 43 characters. The length is
// not decoration: the challenge is public, so the only thing stopping an
// attacker from hashing candidates until one matches is the size of the
// input space.
func newVerifier() string { return randomURLSafe(32) }

// challengeS256 derives the `code_challenge` from a verifier.
//
// BASE64URL(SHA256(ASCII(verifier))), unpadded. This is the one-way step: the
// challenge travels the front channel, the verifier does not.
func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomURLSafe returns n cryptographically random bytes as base64url text.
func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means we must not continue.
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------------------------------------------------------- authorize request

// authorizeURL builds the front-channel request that sends the browser to the IdP.
//
// Every parameter here ends up in the address bar, so nothing secret may be
// added to this function. `code_challenge` is safe precisely because it is a
// hash; `code_verifier` would not be.
func authorizeURL(d *discovery, clientID, redirectURI, scope, state, nonce, challenge string) (*url.URL, error) {
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	u.RawQuery = q.Encode()
	return u, nil
}

// ------------------------------------------------------------ token exchange

// clientAuthMethod is how the client proves it is itself at the token endpoint.
type clientAuthMethod string

const (
	// authBasic puts base64(client_id:client_secret) in the Authorization
	// header. RFC 6749 §2.3.1 names this the preferred form.
	authBasic clientAuthMethod = "client_secret_basic"
	// authPost puts client_id and client_secret in the form body. Same secret,
	// same channel; it differs only in which part of the request carries it,
	// which matters for what gets logged.
	authPost clientAuthMethod = "client_secret_post"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type tokenError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e tokenError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// exchangeCode trades the authorization code for tokens over the back channel.
//
// This is the only request in the whole flow that may carry a secret, because
// it is the only one the browser never touches.
func exchangeCode(
	ctx context.Context, hc *http.Client, d *discovery,
	clientID, clientSecret, redirectURI, code, verifier string,
	auth clientAuthMethod,
) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		// Sent again even though the IdP already has it from the authorization
		// request. RFC 6749 §4.1.3 requires the two to match: it stops a client
		// from being talked into redeeming a code minted for a different callback.
		"code_verifier": {verifier},
	}
	if auth == authPost {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if auth == authBasic {
		// url.QueryEscape per RFC 6749 §2.3.1: the credentials are
		// form-urlencoded before base64, not used raw.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
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
		var te tokenError
		if json.Unmarshal(body, &te) == nil && te.Code != "" {
			return nil, te
		}
		return nil, fmt.Errorf("토큰 엔드포인트 HTTP %s: %s", res.Status, truncate(string(body), 300))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("토큰 응답 파싱 실패: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("ID 토큰이 없다. scope에 openid가 빠졌을 때 이렇게 된다")
	}
	return &tr, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
