// Package jwks fetches an IdP's public keys and verifies JWT signatures with
// them, by hand.
//
// This is the piece chapters 02 and 04 deliberately left out. Without it every
// other check runs on text an attacker could have written: `iss`, `aud`, `exp`
// and `nonce` are only meaningful once you know the IdP actually wrote them.
//
// The single most important rule in this file: **the algorithm comes from the
// key, never from the token.** A token that says `alg: none` or `alg: HS256`
// is not a token that gets verified differently - it is a token that gets
// rejected. Trusting the token's own `alg` is the algorithm-confusion attack.
package jwks

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWK is one key as published at the jwks_uri (RFC 7517).
type JWK struct {
	Kty string `json:"kty"` // key type: we only accept RSA
	Kid string `json:"kid"` // key id: what a token's header points at
	Use string `json:"use"` // "sig" for signing keys
	Alg string `json:"alg"` // what the IdP says this key is for
	N   string `json:"n"`   // RSA modulus, base64url
	E   string `json:"e"`   // RSA public exponent, base64url
}

type Set struct {
	Keys []JWK `json:"keys"`
}

// Key is a usable public key plus the metadata we need to decide what may be
// done with it.
type Key struct {
	Kid string
	Alg string
	Pub *rsa.PublicKey
}

// Bits reports the modulus size, which is what "how strong is this key" means
// for RSA.
func (k Key) Bits() int { return k.Pub.N.BitLen() }

// RSAPublicKey turns the base64url big-endian integers into a real key.
//
// The exponent is almost always 65537, but it is published as bytes and must
// be read as such rather than assumed.
func (j JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("kty=%q 는 지원하지 않는다 (RSA만)", j.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("n 디코딩 실패: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("e 디코딩 실패: %w", err)
	}
	if len(eb) == 0 || len(eb) > 8 {
		return nil, fmt.Errorf("e 길이가 이상하다: %d바이트", len(eb))
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	// A short modulus is not a curiosity, it is a forgeable signature.
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA 키가 %d비트로 너무 짧다", pub.N.BitLen())
	}
	return pub, nil
}

// ------------------------------------------------------------------- cache

// Cache holds the IdP's keys and refetches when it sees an unknown `kid`.
//
// Refetching on an unknown kid is what makes key rollover survivable: the IdP
// starts signing with a new key and clients pick it up without a restart. It
// is also a denial-of-service lever, because anyone can send a token with a
// made-up kid, so the refetch is rate limited.
type Cache struct {
	uri string
	hc  *http.Client

	mu         sync.Mutex
	keys       map[string]Key
	lastFetch  time.Time
	minRefetch time.Duration
	fetches    int
}

func New(jwksURI string, hc *http.Client) *Cache {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Cache{uri: jwksURI, hc: hc, keys: map[string]Key{}, minRefetch: 30 * time.Second}
}

// NewFromSet builds a cache that never fetches. Used by the chapter's offline
// attack suite, where the "IdP" is a keypair we generated ourselves.
func NewFromSet(s Set) (*Cache, error) {
	c := &Cache{keys: map[string]Key{}, minRefetch: time.Hour}
	if err := c.load(s); err != nil {
		return nil, err
	}
	c.lastFetch = time.Now()
	return c, nil
}

func (c *Cache) load(s Set) error {
	n := 0
	for _, j := range s.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue // encryption keys are not ours to verify with
		}
		pub, err := j.RSAPublicKey()
		if err != nil {
			continue // skip key types we do not support rather than failing all
		}
		c.keys[j.Kid] = Key{Kid: j.Kid, Alg: j.Alg, Pub: pub}
		n++
	}
	if n == 0 {
		return fmt.Errorf("쓸 수 있는 RSA 서명 키가 하나도 없다")
	}
	return nil
}

func (c *Cache) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, nil)
	if err != nil {
		return err
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS %s: HTTP %s", c.uri, res.Status)
	}
	var s Set
	if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
		return fmt.Errorf("JWKS 파싱 실패: %w", err)
	}
	c.lastFetch = time.Now()
	c.fetches++
	return c.load(s)
}

// Key returns the key for a kid, fetching once if it is unknown.
func (c *Cache) Key(ctx context.Context, kid string) (Key, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.keys) == 0 {
		if err := c.fetch(ctx); err != nil {
			return Key{}, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	// Unknown kid: the IdP may have rolled its keys. Refetch, but not more
	// often than minRefetch, or a stream of bogus kids becomes a DoS.
	if time.Since(c.lastFetch) < c.minRefetch {
		return Key{}, fmt.Errorf("kid=%q 를 모르고, 방금 갱신해서 아직 다시 안 가져온다 (키 롤오버 아니면 위조)", kid)
	}
	if err := c.fetch(ctx); err != nil {
		return Key{}, err
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return Key{}, fmt.Errorf("kid=%q 가 JWKS에 없다", kid)
}

// Keys lists what is cached, for display.
func (c *Cache) Keys() []Key {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Key, 0, len(c.keys))
	for _, k := range c.keys {
		out = append(out, k)
	}
	return out
}

// Fetches reports how many times we hit the network. Chapter output uses this
// to show that caching works and that rollover costs exactly one refetch.
func (c *Cache) Fetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// --------------------------------------------------------------- verifying

// allowed maps a token `alg` to the hash it requires. Only asymmetric RSA
// algorithms appear here on purpose.
//
// `none` is absent, so it can never be looked up. HS* are absent, so a token
// claiming HMAC can never be verified with an RSA public key - which is the
// algorithm-confusion attack, where the attacker signs with the public key as
// if it were a shared secret.
var allowed = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"PS256": crypto.SHA256, "PS384": crypto.SHA384, "PS512": crypto.SHA512,
}

type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks a compact JWS against the IdP's keys and returns its header.
//
// Order matters. The key is chosen by `kid`, then the algorithm is checked
// against what we allow for that kind of key, and only then is the signature
// computed. At no point does the token get to choose how it is verified.
func (c *Cache) Verify(ctx context.Context, token string) (*Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT는 세 조각이어야 하는데 %d 조각이다", len(parts))
	}
	var h Header
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("헤더 디코딩 실패: %w", err)
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("헤더 파싱 실패: %w", err)
	}

	// Reject before doing any work. An empty signature with alg=none is the
	// oldest JWT attack there is and it only works on verifiers that branch on
	// the token's own claim about itself.
	if strings.EqualFold(h.Alg, "none") {
		return &h, fmt.Errorf("alg=none 은 서명이 없다는 뜻이다. 거부")
	}
	hash, ok := allowed[h.Alg]
	if !ok {
		return &h, fmt.Errorf("alg=%q 는 허용 목록에 없다 (RSA 서명만 받는다)", h.Alg)
	}
	if h.Kid == "" {
		return &h, fmt.Errorf("kid가 없어서 어느 키로 검증할지 알 수 없다")
	}

	key, err := c.Key(ctx, h.Kid)
	if err != nil {
		return &h, err
	}
	// If the IdP labelled the key, the token must agree with the IdP, not the
	// other way around.
	if key.Alg != "" && key.Alg != h.Alg {
		return &h, fmt.Errorf("kid=%s 키는 %s용인데 토큰은 %s라고 주장한다", key.Kid, key.Alg, h.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return &h, fmt.Errorf("서명 디코딩 실패: %w", err)
	}

	// The signature covers exactly "header.payload" as it appeared on the
	// wire, which is why we re-hash the original text instead of re-encoding
	// anything we parsed.
	signingInput := parts[0] + "." + parts[1]
	digest := sum(hash, []byte(signingInput))

	if strings.HasPrefix(h.Alg, "PS") {
		err = rsa.VerifyPSS(key.Pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash})
	} else {
		err = rsa.VerifyPKCS1v15(key.Pub, hash, digest, sig)
	}
	if err != nil {
		return &h, fmt.Errorf("서명이 맞지 않다: %w", err)
	}
	return &h, nil
}

func sum(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(b)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(b)
		return d[:]
	default:
		d := sha256.Sum256(b)
		return d[:]
	}
}
