# 02. Authorization Code + PKCE

00에서 라이브러리가 해준 일을 **표준 라이브러리만으로** 다시 짠다.
`coreos/go-oidc`도 `golang.org/x/oauth2`도 쓰지 않는다.

같은 IdP, 같은 클라이언트, **같은 포트**를 쓴다.
그래야 00의 트레이스와 02의 트레이스가 줄이 맞아서 diff가 의미를 갖는다.
남는 차이가 곧 배울 것이다.

---

## 실행

00 앱과 포트가 같으므로 **동시에 못 띄운다.** 00이 돌고 있으면 먼저 끈다.

```bash
make kc-up      # 로컬 IdP
make run-02     # -> http://localhost:5556
```

로그인 후 `02-authcode-pkce/trace.md` 가 생긴다.

```bash
make diff-traces                              # 00과 왕복 순서 비교
make run-02 CLIENT_AUTH=client_secret_post    # 시크릿이 어디로 옮겨가는지 보기
```

---

## 무엇을 손으로 짰나


| 어디 | 하는 일 | 00에서는 누가 했나 |
|---|---|---|
| [`internal/oidcclient`](../internal/oidcclient) | 디스커버리 파싱, PKCE 계산, 인가 URL 조립, 토큰 교환, JWT 분해·클레임 검증 | `go-oidc` + `x/oauth2` |
| `main.go` | 흐름 제어, `state`/`nonce` 대조, 검증 목록 표시 | 00에서도 앱이 직접 했다 |

> 원래 이 챕터의 `oidc.go` / `idtoken.go` 였다. 04(로그아웃)가 같은 로그인이 필요해지자
> `internal/oidcclient` 로 옮겼다 — 챕터 간 복사 금지가 이 저장소 규칙이라서다.
> 라이브러리를 쓴 게 아니라 **여기서 손으로 쓴 코드가 공용 자리로 간 것**이다.

### 결과 화면이 검증 목록을 보여준다

00에서는 `Verify()` 안에서 조용히 일어나던 검증이, 여기서는 **내가 쓴 코드 한 줄씩**이다.
그래서 로그인 성공 화면이 "무엇을 확인했고 무엇을 아직 안 했는지" 목록으로 나온다.

---

## 체크리스트

- [x] `/.well-known/openid-configuration` 직접 파싱
- [x] `state` 생성·저장·검증 (CSRF 방어)
- [x] `nonce` 생성 후 ID 토큰의 `nonce`와 대조 (리플레이 방어)
- [x] `code_verifier` / `code_challenge` (S256) 직접 계산
- [x] 토큰 엔드포인트로 code 교환
- [x] 클라이언트 인증 방식 비교: `client_secret_basic` vs `client_secret_post`
- [x] 00의 트레이스와 내 트레이스를 diff
- [ ] `private_key_jwt` — **미룸.** JWT에 직접 서명하는 일이라 JWT 챕터의 내용이다

### diff 결과

```
$ make diff-traces

== 백채널 호출 수 ==
  00-first-login-trace   3번
  02-authcode-pkce       2번

== 00은 하는데 02는 안 하는 것 ==
  JWKS 가져오기 (ID 토큰 서명 검증용 공개키)

== 02만 하는 것 ==
  (없음)
```

**차이가 딱 하나다.** 라이브러리를 걷어내고 손으로 다시 짰는데, 네트워크로 오간 것은
JWKS 한 번을 빼면 완전히 같다.

즉 라이브러리가 해주던 일의 대부분은 **왕복이 아니라 계산과 검증**이었다.
`state`/`nonce` 생성, PKCE 해시, 폼 조립, 클레임 대조 — 전부 네트워크에 안 남는 일이다.
트레이스만 보면 00과 02가 거의 같아 보이는데, 코드 양은 전혀 다르다.

그리고 유일하게 남은 그 차이가 **하필 제일 중요한 것**이다.
JWKS를 안 가져왔다는 건 서명을 안 봤다는 뜻이고, 서명을 안 보면 나머지 검증이 전부 무의미하다.

### 일부러 안 한 것

**서명 검증.** JWKS를 가져와 `kid`로 키를 고르는 건 JWKS 챕터다.
지금 이 코드는 ID 토큰의 **글자만 읽고** `iss`/`aud`/`exp`/`nonce`를 대조한다.
그 글자를 누가 썼는지는 확인하지 않는다.

결과 화면과 트레이스 맨 앞에서 이 사실을 계속 지적하도록 해뒀다.
`aud`를 아무리 꼼꼼히 봐도 서명을 안 보면 공격자가 지어낸 토큰이 전부 통과한다.
이건 결함이 아니라 이 챕터가 일부러 남겨둔 경계다. 서명 검증은 JWKS가 필요하고, 그건 다른 조각이다.

---

## 공격 재현 (권장)

두 가지가 이 챕터를 이해하는 데 좋다. 필수는 아니다.

- [ ] `state` 검증을 빼고, 다른 사용자 계정으로 발급된 code를 콜백에 밀어넣어 세션 고정
- [ ] `redirect_uri`를 와일드카드로 등록한 클라이언트를 만들어 code가 엉뚱한 경로로 배달되는 것 확인

---

## 생각해볼 질문

답은 트레이스와 코드(`internal/oidcclient`, `main.go`)에 있다. 별도 답안 파일은 없다.

- `state`와 `nonce`는 각각 무엇을 막나? 왜 하나로 합칠 수 없나?
- PKCE는 원래 모바일 앱을 위한 것이었는데 왜 지금은 웹 앱에도 필수인가?
- Implicit flow는 왜 폐기됐나?
- 디스커버리 문서 안의 `issuer`를, 내가 요청한 issuer와 대조해야 하는 이유는?
- `code_verifier`는 왜 43자 이상이어야 하나? 짧으면 무엇이 뚫리나?
- `aud`가 문자열일 수도 배열일 수도 있다. 배열일 때 `azp`를 추가로 봐야 하는 이유는?
- 토큰 교환 요청에 `redirect_uri`를 왜 또 보내나? IdP는 이미 알고 있는데?
- `client_secret_basic`과 `client_secret_post`는 같은 연결로 같은 시크릿을 보낸다. 그래도 차이가 있다면 무엇인가?

---

## 함정

**`HTTPS required` 403**
Keycloak realm의 `sslRequired` 기본값은 `external`이다.
Docker Desktop이 요청 출발지를 사설 대역 밖 주소(`fdc4:...` 같은 IPv6 ULA)로 넘기면
Keycloak이 외부 접속으로 판단해서 디스커버리부터 403을 낸다.
`localhost`든 `127.0.0.1`이든 똑같이 막힌다.

`realm-demo.json`에 `"sslRequired": "NONE"` 을 넣어 해결했다.
`master` realm은 파일로 임포트하지 않으므로 `make kc-allow-http` 가 컨테이너 안에서 따로 꺼준다.
이게 안 되면 관리 콘솔도 같이 막힌다.

**포트 충돌**
00과 02가 같은 5556을 쓴다. 일부러 그렇게 했다 (트레이스를 diff하려고).
00이 떠 있으면 02는 `address already in use`로 죽으면서 안내를 출력한다.
