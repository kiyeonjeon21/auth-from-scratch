// Package webauthn implements the relying-party side of WebAuthn by hand.
//
// The break from everything else in this repo is the direction of the secret.
// A password, a session id and a bearer token all travel from the holder to
// the verifier, so anyone who intercepts one can replay it. A passkey never
// moves: the authenticator keeps the private key and sends a *signature* over
// a challenge the server just made up.
//
// Two consequences fall out of that, and they are the reason this row exists
// in the comparison table:
//   - stealing the transmitted value gains nothing; it is single-use
//   - the origin is inside the signed data, so a phishing site cannot get a
//     signature that a real site will accept
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// Challenge is a fresh random value the server invents per ceremony.
//
// This is what makes a signature single-use: the authenticator signs over a
// value it has never seen before, so a captured signature proves nothing about
// the next login.
func Challenge() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// clientData is what the browser signs over, verbatim.
//
// The browser fills in Origin itself; the page cannot lie about it. That is
// the phishing defence, and it is enforced by the browser rather than by us.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// AuthenticatorData is the fixed-layout blob the authenticator signs.
//
//	32 bytes  rpIdHash
//	 1 byte   flags
//	 4 bytes  signCount
//	 rest     attested credential data + extensions (registration only)
type AuthenticatorData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	Raw       []byte

	AAGUID       []byte
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
}

const (
	flagUserPresent  = 0x01 // the user touched the authenticator
	flagUserVerified = 0x04 // ...and proved it was them (PIN, biometric)
	flagAttestedData = 0x40 // attested credential data is present
)

func (a AuthenticatorData) UserPresent() bool  { return a.Flags&flagUserPresent != 0 }
func (a AuthenticatorData) UserVerified() bool { return a.Flags&flagUserVerified != 0 }

// ParseAuthenticatorData reads the blob, including the credential public key
// when the attested-data flag is set.
func ParseAuthenticatorData(b []byte) (*AuthenticatorData, error) {
	if len(b) < 37 {
		return nil, fmt.Errorf("authenticatorData가 %d바이트로 너무 짧다 (최소 37)", len(b))
	}
	a := &AuthenticatorData{
		RPIDHash:  b[0:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:37]),
		Raw:       b,
	}
	if a.Flags&flagAttestedData == 0 {
		return a, nil // assertion: no credential data, and none expected
	}
	if len(b) < 55 {
		return nil, fmt.Errorf("attested credential data가 잘렸다")
	}
	a.AAGUID = b[37:53]
	idLen := int(binary.BigEndian.Uint16(b[53:55]))
	if len(b) < 55+idLen {
		return nil, fmt.Errorf("credentialId가 잘렸다")
	}
	a.CredentialID = b[55 : 55+idLen]

	pub, _, err := parseCOSEKey(b[55+idLen:])
	if err != nil {
		return nil, err
	}
	a.PublicKey = pub
	return a, nil
}

// parseCOSEKey reads a COSE_Key (RFC 8152) holding an ES256 public key.
//
// The labels are integers: 1=kty, 3=alg, -1=crv, -2=x, -3=y. Only ES256 on
// P-256 is accepted; anything else is rejected rather than guessed at.
func parseCOSEKey(b []byte) (*ecdsa.PublicKey, int, error) {
	v, n, err := cborDecodeFirst(b)
	if err != nil {
		return nil, 0, fmt.Errorf("COSE 키 파싱 실패: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, fmt.Errorf("COSE 키가 맵이 아니다")
	}
	geti := func(k int64) (int64, bool) {
		x, ok := m[k].(int64)
		return x, ok
	}
	getb := func(k int64) ([]byte, bool) {
		x, ok := m[k].([]byte)
		return x, ok
	}
	if kty, _ := geti(1); kty != 2 {
		return nil, 0, fmt.Errorf("kty=%d 는 지원하지 않는다 (EC2=2만)", kty)
	}
	if alg, _ := geti(3); alg != -7 {
		return nil, 0, fmt.Errorf("alg=%d 는 지원하지 않는다 (ES256=-7만)", alg)
	}
	if crv, _ := geti(-1); crv != 1 {
		return nil, 0, fmt.Errorf("crv=%d 는 지원하지 않는다 (P-256=1만)", crv)
	}
	x, okx := getb(-2)
	y, oky := getb(-3)
	if !okx || !oky {
		return nil, 0, fmt.Errorf("COSE 키에 x 또는 y가 없다")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, 0, fmt.Errorf("공개키 점이 P-256 곡선 위에 없다")
	}
	return pub, n, nil
}

// -------------------------------------------------------------- ceremonies

// Registration is a stored credential: what the server keeps after signup.
//
// Note what is NOT stored: anything secret. The server holds a public key. A
// database dump of this table lets an attacker impersonate nobody, which is
// the structural difference from a password table.
type Registration struct {
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
	SignCount    uint32
}

// Expect describes what a ceremony must match.
type Expect struct {
	Challenge []byte
	Origin    string
	RPID      string
	// RequireUserVerified demands proof it was the human, not just a touch.
	RequireUserVerified bool
}

// VerifyRegistration checks a create() response and returns the credential.
func VerifyRegistration(attestationObject, clientDataJSON []byte, e Expect) (*Registration, error) {
	if err := verifyClientData(clientDataJSON, "webauthn.create", e); err != nil {
		return nil, err
	}
	v, _, err := cborDecodeFirst(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("attestationObject 파싱 실패: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("attestationObject가 맵이 아니다")
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return nil, fmt.Errorf("authData가 없다")
	}
	auth, err := ParseAuthenticatorData(raw)
	if err != nil {
		return nil, err
	}
	if err := checkAuthData(auth, e); err != nil {
		return nil, err
	}
	if auth.PublicKey == nil {
		return nil, fmt.Errorf("등록인데 공개키가 없다")
	}
	return &Registration{
		CredentialID: auth.CredentialID,
		PublicKey:    auth.PublicKey,
		SignCount:    auth.SignCount,
	}, nil
}

// VerifyAssertion checks a get() response against a stored credential.
//
// The signature covers authenticatorData || SHA256(clientDataJSON). Both parts
// matter: the first carries the RP id and flags, the second carries the
// challenge and origin.
func VerifyAssertion(reg *Registration, authenticatorData, clientDataJSON, signature []byte, e Expect) error {
	if err := verifyClientData(clientDataJSON, "webauthn.get", e); err != nil {
		return err
	}
	auth, err := ParseAuthenticatorData(authenticatorData)
	if err != nil {
		return err
	}
	if err := checkAuthData(auth, e); err != nil {
		return err
	}

	sum := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authenticatorData...), sum[:]...)
	digest := sha256.Sum256(signed)

	if !ecdsa.VerifyASN1(reg.PublicKey, digest[:], signature) {
		return fmt.Errorf("서명이 맞지 않다")
	}

	// A counter that fails to advance suggests the credential was cloned: two
	// copies of the same key cannot keep one counter consistent. Authenticators
	// that always report 0 have opted out, so 0 is not treated as a failure.
	if auth.SignCount != 0 || reg.SignCount != 0 {
		if auth.SignCount <= reg.SignCount {
			return fmt.Errorf("signCount가 늘지 않았다 (%d -> %d). 복제된 인증기일 수 있다",
				reg.SignCount, auth.SignCount)
		}
	}
	reg.SignCount = auth.SignCount
	return nil
}

func verifyClientData(b []byte, wantType string, e Expect) error {
	var cd clientData
	if err := json.Unmarshal(b, &cd); err != nil {
		return fmt.Errorf("clientDataJSON 파싱 실패: %w", err)
	}
	if cd.Type != wantType {
		return fmt.Errorf("type이 %q 여야 하는데 %q. 등록 응답을 로그인에 쓰려는 것일 수 있다", wantType, cd.Type)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return fmt.Errorf("challenge 디코딩 실패: %w", err)
	}
	// Compared against the value this server generated moments ago. This is
	// what makes a captured response useless next time.
	if len(got) != len(e.Challenge) || subtleCompare(got, e.Challenge) != 1 {
		return fmt.Errorf("challenge가 내가 낸 값과 다르다. 재전송 공격일 수 있다")
	}
	// The browser writes this field. A phishing origin cannot forge it, so a
	// signature obtained on evil.example will never satisfy this check.
	if cd.Origin != e.Origin {
		return fmt.Errorf("origin이 %q 여야 하는데 %q. 피싱 사이트에서 받은 응답이다", e.Origin, cd.Origin)
	}
	return nil
}

func checkAuthData(a *AuthenticatorData, e Expect) error {
	want := sha256.Sum256([]byte(e.RPID))
	if subtleCompare(a.RPIDHash, want[:]) != 1 {
		return fmt.Errorf("rpIdHash가 %q 의 해시와 다르다. 다른 사이트의 자격증명이다", e.RPID)
	}
	if !a.UserPresent() {
		return fmt.Errorf("user present 플래그가 없다. 사용자가 실제로 조작하지 않았다")
	}
	if e.RequireUserVerified && !a.UserVerified() {
		return fmt.Errorf("user verified 플래그가 없다. 사람 확인(PIN·생체)이 안 됐다")
	}
	return nil
}

// subtleCompare is a constant-time equality check returning 1 when equal.
func subtleCompare(a, b []byte) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}
