# auth-from-scratch

OIDC / OAuth 2.0 / SAML / Token Exchange를 **라이브러리 없이 직접 구현하며** 이해하기 위한 학습 저장소.

목표는 동작하는 프로덕션 코드를 만드는 게 아니라, 라이브러리가 대신 해주던 일을 손으로 한 번씩 해보고 **왜 그렇게 설계됐는지** 를 이해하는 것.

---

## 핵심 관점

프로토콜이 달라 보여도 하는 일은 같다. 결국 **서명된 종이** 를 검증하는 문제다.

| 검증 항목 | 클레임 | 질문 |
|---|---|---|
| 발행자 | `iss` | 누가 발행했나 |
| 대상자 | `aud` | 누구한테 주는 건가 |
| 유효기간 | `exp` / `nbf` | 아직 살아있나 |
| 무결성 | 서명 | 위조가 아닌가 |

SAML이냐 OIDC냐는 이걸 **XML로 하냐 JSON으로 하냐**, 그리고 **브라우저 리다이렉트로 전달하냐 서버 간 호출로 전달하냐** 의 차이일 뿐이다.

---

## 프로토콜 계보

```
        인증(누구인가)   인가(무엇을 허용)   위임(대신 행동)
                    │                │
        ┌───────────┴──┐         ┌───┴──────────┐
        │  SAML 2.0    │         │  OAuth 2.0   │
        │  XML, 엔터프라이즈 │         │  인가 위임 프레임워크 │
        └───────┬──────┘         └───┬──────────┘
                │                    │
                │                ┌───┴──────────┐
                │                │  OIDC        │  ID 토큰으로 인증 추가
                │                └───┬──────────┘
                │                    │
                │                ┌───┴──────────┐
                │                │ Token Exchange│  RFC 8693 → OBO
                │                └───┬──────────┘
                │                    │
        ┌───────┴────────────────────┴──────────┐
        │  공통 기반                              │
        │  서명 검증 · 메타데이터 디스커버리 · 채널 분리  │
        └───────────────────────────────────────┘
```

---

## 디렉토리 구조

```
auth-from-scratch/
├── 01-jwt-by-hand/          # JWT를 라이브러리 없이 만들고 검증
├── 02-authcode-pkce/        # Authorization Code + PKCE 클라이언트 직접 구현
├── 03-jwks-verification/    # 리소스 서버 쪽 토큰 검증
├── 04-token-exchange-obo/   # 위임 체인, delegation vs impersonation
├── 05-saml-reading-notes/   # SAML은 구현하지 않고 읽기만
├── docker/
│   └── keycloak/            # 로컬 IdP
└── notes/                   # 스펙 읽으며 남긴 메모
```

각 디렉토리는 자체 `README.md`와 **직접 답할 수 있어야 하는 질문 목록** 을 가진다. 코드가 돌아가는 것보다 그 질문에 답할 수 있는 게 목표.

---

## 학습 순서

### 01. JWT를 손으로

base64url 인코딩, HMAC/RSA 서명, 검증을 60줄 안에 직접 구현한다.

- [ ] `header.payload.signature` 구조를 직접 조립하고 분해
- [ ] HS256 서명 및 검증
- [ ] RS256 서명 및 검증 (키페어 직접 생성)
- [ ] `alg: none` 공격 재현
- [ ] 알고리즘 혼동 공격 재현 — HS256으로 서명한 토큰을 RS256 공개키로 검증 시도

**답할 수 있어야 하는 질문**
- 왜 검증할 때 토큰에 적힌 `alg`를 믿으면 안 되나?
- base64url은 왜 일반 base64가 아닌가?
- JWT는 암호화된 것인가? (아니라면 민감 정보를 넣으면 안 되는 이유는?)

### 02. Authorization Code + PKCE

Keycloak을 IdP로 띄우고, **OIDC 클라이언트 라이브러리 없이** raw HTTP로 붙는다. 라이브러리를 쓰면 이 단계의 핵심이 통째로 숨겨진다.

- [ ] `/.well-known/openid-configuration` 직접 파싱
- [ ] `state` 생성·저장·검증 (CSRF 방어)
- [ ] `nonce` 생성 후 ID 토큰의 `nonce`와 대조 (리플레이 방어)
- [ ] `code_verifier` / `code_challenge` (S256) 직접 계산
- [ ] 토큰 엔드포인트로 code 교환
- [ ] 받은 ID 토큰 파싱

**답할 수 있어야 하는 질문**
- `state`와 `nonce`는 각각 무엇을 막나? 왜 하나로 합칠 수 없나?
- PKCE는 원래 모바일 앱을 위한 것이었는데 왜 지금은 웹 앱에도 필수인가?
- Implicit flow는 왜 폐기됐나?
- `redirect_uri`를 부분 일치로 비교하면 어떤 공격이 가능한가?

### 03. JWKS와 리소스 서버 검증

이번엔 토큰을 **받는** 쪽을 만든다.

- [ ] JWKS 엔드포인트에서 공개키 목록 가져오기
- [ ] `kid`로 올바른 키 선택
- [ ] JWKS 캐싱 + 키 롤오버 대응 (모르는 `kid`가 오면?)
- [ ] `iss` / `aud` / `exp` 검증
- [ ] Token introspection (RFC 7662)도 구현해서 로컬 검증과 비교

**답할 수 있어야 하는 질문**
- 로컬 검증 vs introspection: 각각 언제 쓰나? 트레이드오프는?
- 토큰을 즉시 무효화해야 한다면 로컬 검증만으로 가능한가?
- `aud` 검증을 빠뜨리면 어떤 공격이 가능한가? (audience confusion)

### 04. Token Exchange / OBO

서비스 A가 유저 토큰을 받아 서비스 B를 호출하는 시나리오를 만든다.

- [ ] RFC 8693 형태의 교환 요청 구성
- [ ] `act` 클레임으로 위임 체인 표현
- [ ] delegation 시나리오 — "유저 대신 A가 요청 중"
- [ ] impersonation 시나리오 — "A가 유저인 척"
- [ ] Azure OBO 흐름과 대조 (같은 개념의 MS 방언)

**답할 수 있어야 하는 질문**
- delegation과 impersonation의 감사 로그는 어떻게 달라지나?
- 위임 체인이 3단계가 되면 `act`는 어떻게 중첩되나?
- 왜 원본 액세스 토큰을 그대로 B에게 전달하면 안 되나?

### 05. SAML — 읽기만

**직접 구현하지 않는다.** XML canonicalization은 지옥이고, XML Signature Wrapping 취약점이 지금도 계속 나온다.

- [ ] 실제 `SAMLResponse`를 base64 디코딩해서 Assertion 구조 뜯어보기
- [ ] `Conditions`, `AudienceRestriction`, `SubjectConfirmation` 해석
- [ ] `crewjam/saml`의 검증 코드 읽기
- [ ] XML Signature Wrapping 공격 원리 이해

**답할 수 있어야 하는 질문**
- SAML Assertion의 어느 부분이 서명되나? 전체인가 일부인가?
- 서명 검증에 성공했는데도 뚫릴 수 있는 이유는?
- SAML과 OIDC를 각각 언제 선택하나?

---

## 실행

```bash
# 로컬 IdP 띄우기
docker run -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev

# 디스커버리 문서 확인
curl http://localhost:8080/realms/master/.well-known/openid-configuration | jq
```

관리 콘솔은 http://localhost:8080 — realm과 client 설정은 `docker/keycloak/README.md` 참고.

---

## 스펙 읽는 순서

| 순서 | 스펙 | 내용 |
|---|---|---|
| 1 | RFC 6749 | OAuth 2.0 코어 |
| 2 | RFC 6750 | Bearer Token 사용법 |
| 3 | RFC 7519 | JWT |
| 4 | OIDC Core 1.0 | 인증 레이어 |
| 5 | RFC 7636 | PKCE |
| 6 | **RFC 9700** | OAuth 2.0 Security BCP |
| 7 | RFC 8693 | Token Exchange |

**RFC 9700은 필독.** 앞의 스펙들을 읽고 나서 보면 "왜 이렇게 설계했는지"가 역으로 이해된다. mix-up 공격, redirect_uri 정확 일치, implicit flow 폐기 이유가 전부 여기 정리돼 있다.

---

## 참고 코드베이스

| 저장소 | 언어 | 왜 |
|---|---|---|
| `ory/fosite` | Go | 스펙을 거의 1:1로 코드에 옮겨놓음. RFC와 나란히 놓고 읽기 최적 |
| `dexidp/dex` | Go | 작고 완결된 OIDC provider. 전체를 다 읽을 수 있는 크기 |
| `panva/jose` | JS | JWS/JWE/JWK 스펙 충실도 최고. 서명 검증 레퍼런스 |
| `panva/openid-client` | JS | OIDC 클라이언트가 실제로 뭘 검증해야 하는지의 정답지 |
| `oauth2-proxy/oauth2-proxy` | Go | 리버스 프록시에서 세션·토큰을 다루는 실전 패턴 |
| `crewjam/saml` | Go | SAML 검증 로직 읽기용 |
| `keycloak/keycloak` | Java | 무겁지만 IdP 전체 구조. 필요한 부분만 발췌 |

---

## 함정 노트

구현하다 걸린 것들을 여기 쌓는다.

- **Audience confusion** — B 서비스용 토큰을 C 서비스가 받아주면 뚫린다. 멀티테넌트에서 특히 위험
- **Mix-up attack** — 여러 IdP를 지원할 때 응답이 어느 IdP에서 왔는지 확인하지 않으면
- **Sender-constrained token** — DPoP(RFC 9449), mTLS. 토큰 탈취 자체를 무력화하는 방향
- **Refresh token rotation** — 재사용이 감지되면 전체 체인을 무효화
- **로그아웃** — front-channel / back-channel logout. SSO의 진짜 어려운 부분은 로그인이 아니라 로그아웃이다

---

## 주의

이 저장소의 코드는 **학습 목적** 이다. 프로덕션에서는 검증된 라이브러리를 써야 한다. 직접 구현한 인증 코드는 거의 항상 취약하며, 이 저장소의 목적은 그 라이브러리들이 무엇을 대신 해주고 있는지 이해하는 것이다.
