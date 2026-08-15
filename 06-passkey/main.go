// Command passkey exercises the WebAuthn relying-party code with a synthetic
// authenticator, so the whole ceremony can be checked without hardware.
//
// The authenticator here is ~40 lines: an ES256 keypair, a counter, and the
// ability to sign authenticatorData||SHA256(clientData). That is genuinely all
// a passkey is. Building the other side makes it obvious why the transmitted
// value is worthless to a thief.
//
// Read 06-passkey/README.md before running.
package main

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
	"os"

	"github.com/kiyeonjeon/auth-from-scratch/internal/webauthn"
)

const (
	rpID   = "localhost"
	origin = "http://localhost:5562"
)

func main() {
	fmt.Println("== Passkey 등록과 로그인, 그리고 공격 ==")
	fmt.Printf("   RP ID %s   origin %s\n\n", rpID, origin)

	auth := newAuthenticator()

	// --- 등록 ---
	regChallenge := webauthn.Challenge()
	attObj, clientData := auth.create(regChallenge, rpID, origin)
	reg, err := webauthn.VerifyRegistration(attObj, clientData, webauthn.Expect{
		Challenge: regChallenge, Origin: origin, RPID: rpID,
	})
	if err != nil {
		fmt.Printf("등록 실패: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   등록 완료. credentialId=%s…\n", b64(reg.CredentialID)[:16])
	fmt.Printf("   서버가 저장한 것: 공개키 (x=%s…)\n", reg.PublicKey.X.String()[:12])
	fmt.Printf("   서버가 저장하지 않은 것: 비밀 전부. 개인키는 인증기를 떠난 적이 없다\n\n")

	// --- 정상 로그인 ---
	fmt.Println("== 정상 로그인 ==")
	ch := webauthn.Challenge()
	ad, cd, sig := auth.get(ch, rpID, origin)
	if err := webauthn.VerifyAssertion(reg, ad, cd, sig, webauthn.Expect{
		Challenge: ch, Origin: origin, RPID: rpID,
	}); err != nil {
		fmt.Printf("   !! 실패: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   OK 통과 (signCount %d)\n\n", reg.SignCount)

	// --- 공격 ---
	fmt.Println("== 공격 ==")
	ok := true
	run := func(name, why string, f func() error) {
		err := f()
		mark, verdict := "OK ", "거부"
		if err == nil {
			mark, verdict = "!! ", "통과"
			ok = false
		}
		fmt.Printf("   %s%-34s %s\n      %s\n", mark, name, verdict, why)
		if err != nil {
			fmt.Printf("      -> %v\n", err)
		}
		fmt.Println()
	}

	// Replay: capture a complete, genuine login and send it again.
	replayCh := webauthn.Challenge()
	rAD, rCD, rSig := auth.get(replayCh, rpID, origin)
	_ = webauthn.VerifyAssertion(reg, rAD, rCD, rSig, webauthn.Expect{
		Challenge: replayCh, Origin: origin, RPID: rpID})
	run("재전송 (가로챈 응답 그대로)",
		"비밀번호였다면 훔친 값을 그대로 쓸 수 있다. 여기선 challenge가 매번 다르다",
		func() error {
			fresh := webauthn.Challenge() // 서버는 새 challenge를 냈다
			return webauthn.VerifyAssertion(reg, rAD, rCD, rSig, webauthn.Expect{
				Challenge: fresh, Origin: origin, RPID: rpID})
		})

	// Phishing: the user is on evil.example, which relays to us.
	run("피싱 (evil.example에서 받은 서명)",
		"브라우저가 origin을 직접 써넣는다. 페이지는 거짓말할 수 없다",
		func() error {
			ch := webauthn.Challenge()
			ad, cd, sig := auth.get(ch, rpID, "https://evil.example")
			return webauthn.VerifyAssertion(reg, ad, cd, sig, webauthn.Expect{
				Challenge: ch, Origin: origin, RPID: rpID})
		})

	// Wrong RP: a credential registered for another site.
	run("다른 사이트의 자격증명",
		"rpIdHash가 서명 안에 들어 있어 사이트를 바꿔치기할 수 없다",
		func() error {
			ch := webauthn.Challenge()
			ad, cd, sig := auth.get(ch, "other.example", origin)
			return webauthn.VerifyAssertion(reg, ad, cd, sig, webauthn.Expect{
				Challenge: ch, Origin: origin, RPID: rpID})
		})

	// Cloned authenticator: same key, counter does not advance.
	run("복제된 인증기 (signCount 정체)",
		"키를 복사해도 카운터를 함께 올릴 수는 없다",
		func() error {
			ch := webauthn.Challenge()
			clone := *auth
			// 복제는 과거 어느 시점에 떠간 것이라 카운터가 뒤처져 있다.
			// 서명하면서 하나 올라가봐야 서버가 이미 본 값을 넘지 못한다.
			if reg.SignCount > 0 {
				clone.count = reg.SignCount - 1
			}
			ad, cd, sig := clone.get(ch, rpID, origin)
			return webauthn.VerifyAssertion(reg, ad, cd, sig, webauthn.Expect{
				Challenge: ch, Origin: origin, RPID: rpID})
		})

	// A different key entirely.
	run("남의 개인키로 서명",
		"공개키가 서버에 등록돼 있으니 다른 키의 서명은 맞지 않는다",
		func() error {
			ch := webauthn.Challenge()
			other := newAuthenticator()
			other.count = reg.SignCount + 5
			ad, cd, sig := other.get(ch, rpID, origin)
			return webauthn.VerifyAssertion(reg, ad, cd, sig, webauthn.Expect{
				Challenge: ch, Origin: origin, RPID: rpID})
		})

	// Registration response replayed as a login.
	run("등록 응답을 로그인에 재사용",
		"clientData의 type이 webauthn.create인지 .get인지 구분한다",
		func() error {
			ch := webauthn.Challenge()
			_, cdCreate := auth.create(ch, rpID, origin)
			ad, _, sig := auth.get(ch, rpID, origin)
			return webauthn.VerifyAssertion(reg, ad, cdCreate, sig, webauthn.Expect{
				Challenge: ch, Origin: origin, RPID: rpID})
		})

	if !ok {
		fmt.Println("   기대와 다른 결과가 있다")
		os.Exit(1)
	}
	fmt.Println("   전부 기대대로다.")
}

// ---------------------------------------------------- synthetic authenticator

// authenticator stands in for a phone or security key.
//
// The private key never leaves this struct, exactly as it never leaves the
// secure element on real hardware. Everything the server sees is derived.
type authenticator struct {
	key   *ecdsa.PrivateKey
	credI []byte
	count uint32
}

func newAuthenticator() *authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	return &authenticator{key: k, credI: id}
}

func (a *authenticator) authData(rpid string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpid))
	a.count++
	out := append([]byte{}, h[:]...)
	flags := byte(0x01 | 0x04) // user present + user verified
	if attested {
		flags |= 0x40
	}
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], a.count)
	out = append(out, c[:]...)
	if !attested {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(a.credI)))
	out = append(out, l[:]...)
	out = append(out, a.credI...)
	return append(out, a.coseKey()...)
}

// coseKey encodes the public key the way an authenticator does.
func (a *authenticator) coseKey() []byte {
	x := pad32(a.key.PublicKey.X)
	y := pad32(a.key.PublicKey.Y)
	// map(5){1:2, 3:-7, -1:1, -2:x, -3:y}
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

func (a *authenticator) clientData(typ string, ch []byte, origin string) []byte {
	b, err := json.Marshal(map[string]any{
		"type": typ, "challenge": b64(ch), "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		panic(err)
	}
	return b
}

func (a *authenticator) create(ch []byte, rpid, origin string) (attObj, clientData []byte) {
	ad := a.authData(rpid, true)
	cd := a.clientData("webauthn.create", ch, origin)
	// attestation "none": map(3){fmt:"none", attStmt:{}, authData:bytes}
	out := []byte{0xa3}
	out = append(out, txt("fmt")...)
	out = append(out, txt("none")...)
	out = append(out, txt("attStmt")...)
	out = append(out, 0xa0)
	out = append(out, txt("authData")...)
	out = append(out, bstrHead(len(ad))...)
	out = append(out, ad...)
	return out, cd
}

func (a *authenticator) get(ch []byte, rpid, origin string) (ad, cd, sig []byte) {
	ad = a.authData(rpid, false)
	cd = a.clientData("webauthn.get", ch, origin)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	s, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		panic(err)
	}
	return ad, cd, s
}

func pad32(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func txt(s string) []byte { return append([]byte{byte(0x60 | len(s))}, s...) }

func bstrHead(n int) []byte {
	if n < 24 {
		return []byte{byte(0x40 | n)}
	}
	if n < 256 {
		return []byte{0x58, byte(n)}
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return append([]byte{0x59}, b[:]...)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
