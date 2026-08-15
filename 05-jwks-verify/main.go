// Command jwks-verify closes the hole chapters 02 and 04 left open.
//
// It does two things and needs no login for either:
//
//  1. Reads the real IdP's JWKS and reports what is actually published there.
//  2. Runs an attack suite against our verifier. The "IdP" for that part is an
//     RSA keypair generated here, because forging a token is the only way to
//     prove a verifier rejects forgeries, and we cannot forge Keycloak's.
//
// Read 05-jwks-verify/README.md before running.
package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kiyeonjeon/auth-from-scratch/internal/jwks"
)

var issuer = flag.String("issuer", "http://localhost:8080/realms/demo", "OIDC issuer URL")

func main() {
	flag.Parse()
	ctx := context.Background()

	fmt.Println("== 1. 진짜 IdP가 published한 키 ==")
	if err := showRealKeys(ctx); err != nil {
		fmt.Printf("   실패: %v\n   Keycloak이 떠 있는지 확인: make kc-up\n", err)
	}

	fmt.Println()
	fmt.Println("== 2. 검증기 공격 시험 ==")
	fmt.Println("   IdP 역할을 할 RSA 키를 여기서 만들어 위조 토큰을 던진다.")
	fmt.Println("   Keycloak의 개인키는 우리에게 없으니, 위조를 증명하려면 이 방법뿐이다.")
	fmt.Println()
	if err := attackSuite(ctx); err != nil {
		fmt.Printf("시험 실패: %v\n", err)
		os.Exit(1)
	}
}

// showRealKeys proves the parser works against a production IdP.
func showRealKeys(ctx context.Context) error {
	d, err := fetchDiscovery(ctx, *issuer)
	if err != nil {
		return err
	}
	c := jwks.New(d.JWKSURI, nil)
	// Asking for a kid we do not have forces the first fetch.
	_, _ = c.Key(ctx, "")
	keys := c.Keys()
	if len(keys) == 0 {
		return fmt.Errorf("키를 못 읽었다")
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Kid < keys[j].Kid })
	fmt.Printf("   %s\n", d.JWKSURI)
	for _, k := range keys {
		fmt.Printf("   kid=%-45s alg=%-6s %d비트\n", k.Kid, k.Alg, k.Bits())
	}
	fmt.Printf("   네트워크 호출 %d회 (이후 요청은 캐시에서 나간다)\n", c.Fetches())
	return nil
}

type discovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func fetchDiscovery(ctx context.Context, iss string) (*discovery, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(iss, "/")+"/.well-known/openid-configuration", nil)
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", res.Status)
	}
	var d discovery
	return &d, json.NewDecoder(res.Body).Decode(&d)
}

// ------------------------------------------------------------ attack suite

const testKid = "test-key-1"

func attackSuite(ctx context.Context) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	cache, err := jwks.NewFromSet(publish(&priv.PublicKey, testKid))
	if err != nil {
		return err
	}

	claims := map[string]any{
		"iss": "https://idp.example", "sub": "alice",
		"aud": "demo-client", "exp": time.Now().Add(time.Hour).Unix(),
	}

	type tc struct {
		name       string
		token      string
		wantAccept bool
		why        string
	}
	cases := []tc{
		{"정상 토큰 (RS256, 올바른 키)", signRS256(priv, testKid, claims), true,
			"이건 통과해야 한다. 통과 안 하면 검증기가 망가진 것"},
		{"alg: none", noneToken(claims), false,
			"서명이 없다고 토큰이 주장한다. 가장 오래된 JWT 공격"},
		{"alg 혼동 (공개키를 HMAC 비밀로)", algConfusion(&priv.PublicKey, testKid, claims), false,
			"공개키는 공개다. HS256으로 받아주면 누구나 서명할 수 있다"},
		{"페이로드 변조 (sub=admin)", tamper(signRS256(priv, testKid, claims), "admin"), false,
			"서명은 header.payload 전체를 덮는다. 한 글자만 바꿔도 깨진다"},
		{"모르는 kid", signRS256(priv, "attacker-key", claims), false,
			"공격자가 자기 키로 서명하고 kid를 지어냈다"},
		{"kid 없음", signRS256(priv, "", claims), false,
			"어느 키로 검증할지 알 수 없다"},
	}

	ok := true
	for _, c := range cases {
		_, err := cache.Verify(ctx, c.token)
		accepted := err == nil
		verdict := "거부"
		if accepted {
			verdict = "통과"
		}
		mark := "OK "
		if accepted != c.wantAccept {
			mark = "!! "
			ok = false
		}
		fmt.Printf("   %s%-32s %s\n", mark, c.name, verdict)
		fmt.Printf("      %s\n", c.why)
		if err != nil {
			fmt.Printf("      -> %v\n", err)
		}
		fmt.Println()
	}
	if !ok {
		return fmt.Errorf("기대와 다른 결과가 있다")
	}
	fmt.Println("   전부 기대대로다.")
	return nil
}

// publish turns a public key into the JWKS an IdP would serve.
func publish(pub *rsa.PublicKey, kid string) jwks.Set {
	return jwks.Set{Keys: []jwks.JWK{{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: b64(pub.N.Bytes()),
		E: b64(bigEndian(pub.E)),
	}}}
}

func signRS256(priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	h := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid != "" {
		h["kid"] = kid
	}
	input := seg(h) + "." + seg(claims)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(sig)
}

// noneToken is the classic: claim there is no signature and leave it empty.
func noneToken(claims map[string]any) string {
	return seg(map[string]any{"alg": "none", "typ": "JWT", "kid": testKid}) + "." + seg(claims) + "."
}

// algConfusion signs with the RSA *public* key used as an HMAC secret.
//
// It works against verifiers that read `alg` from the token and then pick the
// matching primitive: they hand the public key to HMAC, and the public key is
// something the attacker already has.
func algConfusion(pub *rsa.PublicKey, kid string, claims map[string]any) string {
	input := seg(map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid}) + "." + seg(claims)
	mac := hmac.New(sha256.New, pub.N.Bytes())
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil))
}

// tamper rewrites `sub` while keeping the original signature.
func tamper(token, sub string) string {
	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["sub"] = sub
	return parts[0] + "." + seg(m) + "." + parts[2]
}

func seg(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b64(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func bigEndian(e int) []byte {
	var out []byte
	for e > 0 {
		out = append([]byte{byte(e & 0xff)}, out...)
		e >>= 8
	}
	return out
}
