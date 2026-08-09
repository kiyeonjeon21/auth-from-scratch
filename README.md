# auth-from-scratch

인증의 **근본 building block** 을 라이브러리 없이 하나씩 만들어보고 나란히 비교하는 학습 저장소.

세션·토큰·비밀번호·passkey·요청 서명·로그아웃 같은 조각들이 무엇이고,
**각 조각이 앞의 무엇이 부족해서 나왔으며 무엇을 포기했는지** 를 손으로 확인하는 것이 목표다.
프로덕션 코드가 아니라 이해가 목적이다.

---

## 결과물은 코드가 아니라 표다

[`notes/comparison.md`](notes/comparison.md)

| 방식 | 상태 위치 | 증명 대상 | 훔치면 끝? | 취소 | 신뢰의 뿌리 | 피싱 저항 |
|---|---|---|---|---|---|---|
| 세션 + 쿠키 | | | | | | |
| JWT bearer | 없음 | 아는 것 | 예 | 어려움 | 발급자 서명키 | 없음 |
| OIDC 로그인 | IdP + 클라이언트 | 아는 것 | 예 | 부분적 | IdP 서명키 | 없음 |
| Passkey | | | | | | |
| DPoP | | | | | | |

챕터 하나를 끝낼 때마다 한 줄이 채워진다.
개별 방식은 다른 데서도 배울 수 있지만 **이 표는 직접 만들어봐야 생긴다.**

---

## 용어부터

세 단어가 자주 섞여 쓰이는데 층위가 다르다.

| | 무엇인가 |
|---|---|
| **JWT** | 데이터 **형식**. 서명된 JSON. 그 자체로는 인증이 아니다 |
| **OAuth 2.0** | **위임** 프레임워크. "이 앱이 내 대신 접근해도 된다" |
| **OIDC** | OAuth 위에 얹은 **인증** 레이어. "이 사용자가 누구다" |
| **SSO** | **성질**. 한 번 로그인으로 여러 곳. 구현 방식이 아니다 |

SSO는 특히 오해하기 쉽다.
SAML로도, OIDC로도, Kerberos로도, 그냥 공유 쿠키로도 된다.
같은 SSO를 서로 다른 방식으로 만들어보면 차이가 선명해진다.

---

## 네 가지 질문

방식을 나열하지 않고 질문으로 묶는다. 그래야 비교가 된다.

### A. 로그인 상태를 어디에 두나

| | 방식 | 상태 |
|---|---|---|
| **A1** | 세션 + 쿠키 — 서버가 기억한다 | |
| **A2** | 서명된 토큰 (JWT) — 아무도 기억하지 않는다 | → [agent-identity-lab](../agent-identity-lab) phase 2 |
| **A3** | 로그아웃 — 기억을 지우는 문제 | |

### B. 무엇으로 사람을 증명하나

| | 방식 | 상태 |
|---|---|---|
| **B1** | 비밀번호 — 아는 것 | |
| **B2** | TOTP / 매직링크 — 받는 것 | |
| **B3** | Passkey / WebAuthn — 가진 것, 기기가 서명 | |

### C. 요청 자체를 어떻게 보호하나

| | 방식 | 상태 |
|---|---|---|
| **C1** | Bearer — 가지면 끝 | → 00·02에서 확인 |
| **C2** | HMAC 요청 서명 — AWS SigV4 방식 | |
| **C3** | DPoP / mTLS — 토큰을 키에 묶기 | |

### D. 남에게 어떻게 맡기나

| | 방식 | 상태 |
|---|---|---|
| **D1** | OAuth 2.0 / OIDC | **완료** — [00](00-first-login-trace), [02](02-authcode-pkce) |
| **D2** | SAML — 구현하지 않고 읽기만 | |

---

## agent-identity-lab 과의 분담

[`../agent-identity-lab`](../agent-identity-lab) 은 **agent 서비스에 인증을 붙이는** 저장소다.
OIDC 줄기를 이미 깊게 팠다. 여기서 다시 하지 않는다.

| 주제 | 어디서 |
|---|---|
| 자작 IdP, RS256/JWKS, alg 혼동 공격 | lab phase 2 |
| Authorization Code + PKCE | lab phase 3 (여기 02와 중복. 여기 것은 비교 기준으로 남김) |
| 리프레시, 수명 불일치, durable 세션 | lab phase 5 |
| Token Exchange, OBO, 중첩 `act` | lab phase 4·10·14 |
| step-up consent, confused deputy | lab phase 6·8 |

**저쪽은 응용, 여기는 근본이다.**
저쪽은 "agent에게 어떻게 신원을 주고 사용자 권한을 안전하게 위임하나"라는 한 문제를
OIDC/OBO 한 줄기로 깊게 판다.
여기는 "인증의 building block이 애초에 무엇이고 왜 각각이 필요한가"를 넓게 본다.
세션, Passkey, 요청 서명, 로그아웃, SAML — OIDC가 덮지 않는 조각들이다.

---

## 디렉토리 구조

```
auth-from-scratch/
├── 00-first-login-trace/    D1. 라이브러리로 로그인 1회 + 와이어 캡처
├── 02-authcode-pkce/        D1. 같은 것을 라이브러리 없이
├── internal/
│   └── wiretrace/           모든 방식을 같은 형식으로 기록하는 공용 레코더
├── docker/keycloak/         로컬 IdP. realm 설정은 코드로
├── notes/
│   ├── comparison.md        결과물. 방식 비교표
│   └── diagrams.md          그림 목록
├── docker-compose.yml
└── Makefile
```

번호는 만든 순서다. 읽는 순서가 아니다. 읽는 순서는 위의 A~D다.

Go 모듈 하나에 챕터가 `main` 패키지로 들어간다.
공용 코드는 `internal/`에 두고 챕터 사이에 복사하지 않는다.

### `internal/wiretrace` 가 이 저장소의 엔진이다

모든 HTTP 왕복을 프론트채널/백채널로 나눠 기록하고, 파라미터마다 "왜 있나" 주석을 붙여
마크다운으로 떨군다. **같은 렌즈로 다른 방식을 찍으면 차이가 눈에 보인다.**

세션 로그인 트레이스와 OIDC 트레이스와 Passkey 트레이스를 같은 형식으로 놓고 비교하는 것이
표를 채우는 방법이다.

---

## 그림

용어를 모르는 상태에서 시작할 수 있게 세 장을 순서대로 둔다.
전체 목록은 [`notes/diagrams.md`](notes/diagrams.md).

1. [가장 쉬운 그림 - 로그인이란](https://app.excalidraw.com/s/AU3bkHPBsIE/4o7ZsmOJtq2) — 프로토콜 용어 없음
2. [로그인 한 번에 무슨 일이 일어나나](https://app.excalidraw.com/s/AU3bkHPBsIE/VeJ6rXc0py) — 1번과 같은 레이아웃에 진짜 이름
3. [PKCE - 가루와 원본](https://app.excalidraw.com/s/AU3bkHPBsIE/74Xaul0gvdJ)

---

## 각 챕터의 완료 조건

**필수는 둘뿐이다.**

1. 동작하는 최소 코드 — 그 방식을 손으로 시연
2. **`notes/comparison.md` 에 한 줄 추가** — 시연한 것에서 채운다, 추측 금지

권장 (하면 이해가 깊어지는 것, 안 해도 됨)

- 공격 재현 — 검증을 한 줄 빼면 어떻게 뚫리는지 실제로 실행
- README에 "이 방식은 앞의 무엇이 부족해서 나왔나" 한 문단
- 각 README의 `생각해볼 질문` 에 스스로 답해보기 (별도 답안 파일은 없다. 답은 코드와 트레이스에 있다)

---

## 실행

```bash
make kc-up      # 로컬 IdP (D 계열 챕터에서 필요)
make run-00     # -> http://localhost:5556
make run-02     # 00과 같은 포트. 동시에 못 띄운다
make help       # 전체 타깃
```

로그인 계정 `alice` / `alice`, 관리 콘솔 http://localhost:8080 (`admin` / `admin`).

주의할 점은 [`docker/keycloak/README.md`](docker/keycloak/README.md) 에 모아뒀다.
realm 설정은 코드이고, 파일을 고쳤으면 `make kc-up` 이 아니라 **`make kc-reset`** 이다.

---

## 스펙 읽는 순서

| 스펙 | 내용 | 관련 |
|---|---|---|
| RFC 6265 | HTTP 쿠키 | A1 |
| RFC 7519 | JWT | A2 |
| RFC 6749 / 6750 | OAuth 2.0 코어, Bearer 사용법 | C1, D1 |
| OIDC Core 1.0 | 인증 레이어 | D1 |
| RFC 7636 | PKCE | D1 |
| **RFC 9700** | OAuth 2.0 Security BCP | 전체 |
| RFC 6238 | TOTP | B2 |
| WebAuthn L3 / CTAP2 | Passkey | B3 |
| RFC 9421 | HTTP Message Signatures | C2 |
| RFC 9449 | DPoP | C3 |
| OIDC RP-Initiated / Back-Channel Logout | 로그아웃 | A3 |

**RFC 9700은 필독.**
앞의 것들을 읽고 나서 보면 "왜 이렇게 설계했는지"가 역으로 이해된다.

---

## 참고 코드베이스

| 저장소 | 언어 | 왜 |
|---|---|---|
| `ory/fosite` | Go | 스펙을 거의 1:1로 옮겨놓음. RFC와 나란히 읽기 최적 |
| `dexidp/dex` | Go | 작고 완결된 OIDC provider |
| `go-webauthn/webauthn` | Go | B3의 정답지 |
| `oauth2-proxy/oauth2-proxy` | Go | 세션·토큰을 다루는 실전 패턴. A1, A3 |
| `crewjam/saml` | Go | D2 읽기용 |
| `panva/jose` | JS | JWS/JWE/JWK 스펙 충실도 최고 |

---

## 주의

이 저장소의 코드는 **학습 목적** 이다.
프로덕션에서는 검증된 라이브러리를 써야 한다.
직접 구현한 인증 코드는 거의 항상 취약하며, 이 저장소의 목적은 그 라이브러리들이
무엇을 대신 해주고 있는지 이해하는 것이다.
