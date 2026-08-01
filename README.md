# auth-from-scratch

OIDC / OAuth 2.0 / SAML / Token Exchange를 **라이브러리 없이 직접 구현하며** 이해하기 위한 학습 저장소.

목표는 동작하는 프로덕션 코드를 만드는 게 아니라, 라이브러리가 대신 해주던 일을 손으로 한 번씩 해보고 **왜 그렇게 설계됐는지** 를 이해하는 것.

---

## 핵심 관점

프로토콜이 달라 보여도 하는 일은 같다.
결국 **서명된 종이** 를 검증하는 문제다.

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
OAuth 2.0  (RFC 6749)
│  인가 위임 프레임워크. "이 앱이 내 리소스에 접근해도 된다"
│
├── OIDC Core 1.0
│     ID 토큰을 얹어 인증 레이어 추가. "이 사용자가 누구다"
│
└── Token Exchange (RFC 8693)
      토큰을 다른 토큰으로 교환. 위임 체인, OBO

SAML 2.0
   같은 문제를 XML과 브라우저 POST로 푼 별도 계보. 엔터프라이즈 SSO

공통 기반
   서명 검증 · 메타데이터 디스커버리 · 프론트채널/백채널 분리
```

---

## 학습 방식

**탑다운으로 간다.**
부품부터 쌓아 올리지 않는다.

먼저 라이브러리를 **일부러 써서** 로그인 하나를 끝까지 성공시키고, 그 과정의 모든 HTTP 왕복을 캡처한다.
그 다음 캡처된 요청을 한 줄씩 뜯으면서 "이 파라미터는 왜 있나"를 질문으로 만든다.
그 질문 목록이 01 이후 챕터의 목차가 된다.

이 순서를 지키는 이유는, 라이브러리가 뭘 숨겨줬는지 이해하는 게 목적이기 때문이다.
숨겨진 상태를 한 번도 안 보고 시작하면 뭘 벗겨내고 있는지 알 수 없다.

### 언어는 Go로 고정

참고할 레퍼런스 구현(`fosite`, `dex`, `oauth2-proxy`, `crewjam/saml`)이 전부 Go다.
내가 직접 쓴 코드와 레퍼런스의 같은 부분을 나란히 놓고 비교할 수 있는 게 이 저장소의 최대 레버리지다.
언어가 갈리면 그게 안 된다.

### 각 챕터의 완료 조건

코드가 돌아가는 것은 완료 조건이 아니다.
각 챕터는 아래 세 가지를 모두 채워야 끝난다.

1. 동작하는 최소 코드
2. `ANSWERS.md` - 챕터의 질문 목록에 대한 자기 답변. 스펙 인용이 아니라 자기 말로
3. 공격 재현 1개 - 검증을 한 줄 빼면 어떻게 뚫리는지 실제로 실행해서 확인

---

## 디렉토리 구조

```
auth-from-scratch/
├── 00-first-login-trace/    # 라이브러리로 일단 성공 + 와이어 캡처 (진입점)
├── 01-jwt-by-hand/          # JWT를 라이브러리 없이 만들고 검증
├── 02-authcode-pkce/        # Authorization Code + PKCE 클라이언트 직접 구현
├── 03-jwks-verification/    # 리소스 서버 쪽 토큰 검증
├── 04-session-and-refresh/  # 토큰을 어디에 두나, 리프레시와 rotation
├── 05-logout/               # front-channel / back-channel logout
├── 06-token-exchange-obo/   # 위임 체인, delegation vs impersonation
├── 07-saml-reading-notes/   # SAML은 구현하지 않고 읽기만
├── 08-sender-constrained/   # DPoP, mTLS (선택)
├── internal/
│   └── wiretrace/           # HTTP 왕복을 주석 달린 마크다운으로 떨구는 공용 레코더
├── docker/
│   └── keycloak/            # 로컬 IdP. realm 설정은 코드로 관리
├── docker-compose.yml
├── Makefile
└── notes/                   # 스펙 읽으며 남긴 메모
```

Go 모듈 하나에 챕터가 `main` 패키지로 들어간다.
`go run ./00-first-login-trace` 식으로 실행하고, 공용 코드는 `internal/`에 둔다.
챕터 사이에 코드를 복사하지 않는다.

---

## 학습 순서

### 00. 첫 로그인 트레이스

**이 챕터에서만 라이브러리를 쓴다.**
`golang.org/x/oauth2` + `go-oidc`로 로그인을 5분 만에 성공시킨다.
목적은 구현이 아니라 관찰이다.

- [ ] `make kc-up` 으로 IdP 기동. realm은 `docker/keycloak/realm-demo.json` 에서 자동 임포트된다
- [ ] `make run-00` 후 브라우저에서 로그인 성공시키기
- [ ] 생성된 `00-first-login-trace/trace.md` 읽기. 왕복 전체가 파라미터 주석과 함께 들어있다
- [ ] `**TODO**` 로 표시된 값을 전부 찾아서 답 찾기
- [ ] 브라우저 개발자도구(Preserve log)로 앱이 못 보는 브라우저-IdP 구간 확인
- [ ] `ANSWERS.md` 채우기

**답할 수 있어야 하는 질문**
- 로그인 한 번에 프론트채널 몇 번, 백채널 몇 번이 오가나?
- `code`는 왜 프론트채널로 와도 되고, `client_secret`은 왜 안 되나?
- 라이브러리가 대신 해준 것과, 여전히 내가 직접 해야 하는 것은 각각 무엇인가?
  (힌트: `code_verifier`는 해주고 `state`와 `nonce`는 안 해준다. 왜 그 선이 거기인가?)
- ID 토큰에는 `aud`가 있는데 액세스 토큰에는 없다. 리소스 서버는 무엇을 보고 자기 것이라 판단하나?
- 디스커버리 문서 한 번으로 대체된 하드코딩은 몇 개인가? 그 대신 무엇을 신뢰하게 되었나?

### 01. JWT를 손으로

base64url 인코딩, HMAC/RSA 서명, 검증을 60줄 안에 직접 구현한다.

- [ ] `header.payload.signature` 구조를 직접 조립하고 분해
- [ ] HS256 서명 및 검증
- [ ] RS256 서명 및 검증 (키페어 직접 생성)
- [ ] 00에서 받은 실제 ID 토큰을 내 파서로 디코딩

**공격 재현**
- [ ] `alg: none` 공격
- [ ] 알고리즘 혼동 공격. HS256으로 서명한 토큰을 RS256 공개키로 검증 시도

**답할 수 있어야 하는 질문**
- 왜 검증할 때 토큰에 적힌 `alg`를 믿으면 안 되나?
- base64url은 왜 일반 base64가 아닌가?
- JWT는 암호화된 것인가? (아니라면 민감 정보를 넣으면 안 되는 이유는?)

### 02. Authorization Code + PKCE

00에서 라이브러리가 해준 일을 raw HTTP로 다시 짠다.
00의 `trace.md`와 내 구현의 왕복을 대조하는 게 이 챕터의 핵심이다.

- [ ] `/.well-known/openid-configuration` 직접 파싱
- [ ] `state` 생성·저장·검증 (CSRF 방어)
- [ ] `nonce` 생성 후 ID 토큰의 `nonce`와 대조 (리플레이 방어)
- [ ] `code_verifier` / `code_challenge` (S256) 직접 계산
- [ ] 토큰 엔드포인트로 code 교환
- [ ] 클라이언트 인증 방식 비교: `client_secret_basic` vs `private_key_jwt`
- [ ] 00의 트레이스와 내 트레이스를 diff

**공격 재현**
- [ ] `state` 검증을 빼고 CSRF로 세션 고정
- [ ] `redirect_uri`를 접두사 일치로 비교하게 바꾸고 code 탈취

**답할 수 있어야 하는 질문**
- `state`와 `nonce`는 각각 무엇을 막나? 왜 하나로 합칠 수 없나?
- PKCE는 원래 모바일 앱을 위한 것이었는데 왜 지금은 웹 앱에도 필수인가?
- Implicit flow는 왜 폐기됐나?
- `private_key_jwt`는 `client_secret`에 비해 무엇을 더 막아주나?

### 03. JWKS와 리소스 서버 검증

이번엔 토큰을 **받는** 쪽을 만든다.

- [ ] JWKS 엔드포인트에서 공개키 목록 가져오기
- [ ] `kid`로 올바른 키 선택
- [ ] JWKS 캐싱 + 키 롤오버 대응 (모르는 `kid`가 오면?)
- [ ] `iss` / `aud` / `exp` 검증
- [ ] Token introspection (RFC 7662)도 구현해서 로컬 검증과 비교

**공격 재현**
- [ ] `aud` 검증을 빼고 다른 서비스용 토큰으로 접근 (audience confusion)
- [ ] JWKS를 캐시만 하고 갱신하지 않을 때 키 롤오버 후 전면 장애 재현

**답할 수 있어야 하는 질문**
- 로컬 검증 vs introspection: 각각 언제 쓰나? 트레이드오프는?
- 토큰을 즉시 무효화해야 한다면 로컬 검증만으로 가능한가?
- 모르는 `kid`가 왔을 때 즉시 JWKS를 다시 받으면 어떤 문제가 생기나?

### 04. 세션, 저장 위치, 리프레시

여기가 실무에서 제일 많이 틀리는 지점이다.
프로토콜이 아니라 설계 판단의 영역이라 스펙에 답이 안 적혀 있다.

- [ ] 토큰을 브라우저에 두는 경우와 서버 세션에 두는 경우를 둘 다 구현
- [ ] httpOnly + Secure + SameSite 쿠키 조합 실험
- [ ] BFF 패턴. 브라우저는 세션 쿠키만, 토큰은 백엔드가 보관
- [ ] `refresh_token`으로 액세스 토큰 갱신
- [ ] Refresh token rotation 구현
- [ ] 재사용 감지 시 체인 전체 무효화

**공격 재현**
- [ ] localStorage에 액세스 토큰을 두고 XSS 한 줄로 탈취
- [ ] rotation 없이 리프레시 토큰을 재사용해 무한 연장

**답할 수 있어야 하는 질문**
- 액세스 토큰을 localStorage에 두면 안 되는 이유를 XSS 말고도 댈 수 있나?
- SameSite=Lax가 막아주는 것과 못 막는 것은?
- rotation에서 재사용이 감지됐을 때 왜 "그 토큰"이 아니라 "체인 전체"를 죽이나?
- 액세스 토큰 수명을 5분으로 짧게 잡는 게 실제로 무엇을 사주는가?

### 05. 로그아웃

SSO의 진짜 어려운 부분은 로그인이 아니라 로그아웃이다.
세션이 IdP, RP, 브라우저 세 곳에 흩어져 있고 어느 하나만 지워서는 로그아웃이 되지 않는다.

- [ ] RP-Initiated Logout. `end_session_endpoint`로 IdP 세션 종료
- [ ] `id_token_hint`와 `post_logout_redirect_uri` 처리
- [ ] Front-channel logout. iframe으로 각 RP에 알림
- [ ] Back-channel logout. IdP가 각 RP에 logout token을 POST
- [ ] `sid` 클레임으로 어느 세션을 죽일지 특정

**공격 재현**
- [ ] RP 세션만 지우고 IdP 세션을 남긴 뒤, 다시 로그인 버튼을 눌러 무인증 재로그인 확인

**답할 수 있어야 하는 질문**
- 로그아웃을 눌렀는데 다시 로그인 버튼을 누르면 바로 들어가지는 이유는?
- front-channel logout이 서드파티 쿠키 차단 환경에서 깨지는 이유는?
- back-channel logout token은 ID 토큰과 무엇이 다른가? 왜 `nonce`가 없나?
- RP가 10개일 때 하나가 응답하지 않으면 로그아웃은 성공인가 실패인가?

### 06. Token Exchange / OBO

서비스 A가 유저 토큰을 받아 서비스 B를 호출하는 시나리오를 만든다.

- [ ] RFC 8693 형태의 교환 요청 구성
- [ ] `act` 클레임으로 위임 체인 표현
- [ ] delegation 시나리오. "유저 대신 A가 요청 중"
- [ ] impersonation 시나리오. "A가 유저인 척"
- [ ] Azure OBO 흐름과 대조 (같은 개념의 MS 방언)

**공격 재현**
- [ ] 원본 액세스 토큰을 그대로 B에게 전달하고, B가 그 토큰으로 C까지 호출하는 것 확인

**답할 수 있어야 하는 질문**
- delegation과 impersonation의 감사 로그는 어떻게 달라지나?
- 위임 체인이 3단계가 되면 `act`는 어떻게 중첩되나?
- 왜 원본 액세스 토큰을 그대로 B에게 전달하면 안 되나?
- 교환된 토큰의 수명은 원본보다 길어도 되나?

### 07. SAML - 읽기만

**직접 구현하지 않는다.**
XML canonicalization은 지옥이고, XML Signature Wrapping 취약점이 지금도 계속 나온다.

- [ ] 실제 `SAMLResponse`를 base64 디코딩해서 Assertion 구조 뜯어보기
- [ ] `Conditions`, `AudienceRestriction`, `SubjectConfirmation` 해석
- [ ] `crewjam/saml`의 검증 코드 읽기
- [ ] XML Signature Wrapping 공격 원리 이해 (재현은 논문/PoC 읽기로 대체)

**답할 수 있어야 하는 질문**
- SAML Assertion의 어느 부분이 서명되나? 전체인가 일부인가?
- 서명 검증에 성공했는데도 뚫릴 수 있는 이유는?
- SAML과 OIDC를 각각 언제 선택하나?

### 08. Sender-constrained token (선택)

여기까지의 모든 토큰은 bearer다.
훔치면 그대로 쓸 수 있다는 뜻이다.
그 전제를 깨는 방향.

- [ ] DPoP (RFC 9449) proof JWT 생성 및 검증
- [ ] `cnf` 클레임으로 키 바인딩
- [ ] mTLS 바인딩과 개념 비교

**답할 수 있어야 하는 질문**
- DPoP는 토큰 탈취를 막는가, 아니면 탈취 이후를 막는가?
- DPoP proof에 `nonce`가 왜 필요한가?
- DPoP와 mTLS 중 언제 무엇을 고르나?

---

## 실행

```bash
make kc-up      # 로컬 IdP 기동. demo realm 자동 임포트, 디스커버리 응답까지 대기
make run-00     # 00-first-login-trace 실행 -> http://localhost:5556
make help       # 전체 타깃
```

로그인 계정은 `alice` / `alice`, 관리 콘솔은 http://localhost:8080 (`admin` / `admin`).

주의할 점 세 가지.

**realm 설정은 코드다.**
`docker/keycloak/realm-demo.json` 이 유일한 소스다.
관리 콘솔에서 클릭으로 바꾼 것은 다음 리셋 때 전부 날아간다.
파일을 고쳤으면 `make kc-up` 이 아니라 **`make kc-reset`** 이다.
`kc-up`은 기존 볼륨을 그대로 재사용해서 변경이 조용히 무시된다.

**버전은 핀으로 고정한다.**
`26.2`로 박혀 있다.
`latest`로 바꾸면 feature flag 이름이 바뀌었을 때 두 챕터 뒤에서 깨진다.
Token exchange는 preview라 플래그가 필요한데, 26.2 기준 표준 방식은 `token-exchange-standard`(v2)이고 `token-exchange`는 레거시(v1)다.
헷갈리기 쉬우니 버전을 올릴 때는 먼저 확인한다.

```bash
docker run --rm quay.io/keycloak/keycloak:26.2 build --help-all | grep -A2 token-exchange
```

**`master` realm을 앱 realm으로 쓰지 않는다.**
master는 관리용이라 클라이언트 설정과 토큰 동작이 미묘하게 다르다.
자세한 것은 `docker/keycloak/README.md` 참고.

---

## 스펙 읽는 순서

| 순서 | 스펙 | 내용 | 관련 챕터 |
|---|---|---|---|
| 1 | RFC 6749 | OAuth 2.0 코어 | 02 |
| 2 | RFC 6750 | Bearer Token 사용법 | 03 |
| 3 | RFC 7519 | JWT | 01 |
| 4 | OIDC Core 1.0 | 인증 레이어 | 02 |
| 5 | RFC 7636 | PKCE | 02 |
| 6 | RFC 7662 | Token Introspection | 03 |
| 7 | **RFC 9700** | OAuth 2.0 Security BCP | 전체 |
| 8 | OIDC RP-Initiated Logout / Back-Channel Logout | 로그아웃 | 05 |
| 9 | RFC 8693 | Token Exchange | 06 |
| 10 | RFC 9449 | DPoP | 08 |

**RFC 9700은 필독.**
앞의 스펙들을 읽고 나서 보면 "왜 이렇게 설계했는지"가 역으로 이해된다.
mix-up 공격, redirect_uri 정확 일치, implicit flow 폐기 이유가 전부 여기 정리돼 있다.

---

## 참고 코드베이스

| 저장소 | 언어 | 왜 |
|---|---|---|
| `ory/fosite` | Go | 스펙을 거의 1:1로 코드에 옮겨놓음. RFC와 나란히 놓고 읽기 최적 |
| `dexidp/dex` | Go | 작고 완결된 OIDC provider. 전체를 다 읽을 수 있는 크기 |
| `coreos/go-oidc` | Go | 00에서 쓸 클라이언트. 나중에 02의 내 구현과 대조 |
| `oauth2-proxy/oauth2-proxy` | Go | 리버스 프록시에서 세션·토큰을 다루는 실전 패턴. 04, 05의 정답지 |
| `crewjam/saml` | Go | SAML 검증 로직 읽기용 |
| `panva/jose` | JS | JWS/JWE/JWK 스펙 충실도 최고. 서명 검증 레퍼런스 |
| `keycloak/keycloak` | Java | 무겁지만 IdP 전체 구조. 필요한 부분만 발췌 |

---

## 함정 노트

구현하다 걸린 것들을 여기 쌓는다.
챕터로 승격할 만큼 커지면 승격한다.

- **Mix-up attack** - 여러 IdP를 지원할 때 응답이 어느 IdP에서 왔는지 확인하지 않으면
- **Audience confusion** - B 서비스용 토큰을 C 서비스가 받아주면 뚫린다. 멀티테넌트에서 특히 위험
- **Scope와 audience 혼동** - scope는 "무엇을 할 수 있나", audience는 "누구에게 보여줄 것인가". 자주 섞인다
- **시계 오차** - `exp` 검증에 leeway를 얼마나 줄 것인가. 0이면 깨지고 크면 뚫린다
- **에러 응답에서의 정보 노출** - `error_description`에 뭘 담아도 되나

---

## 주의

이 저장소의 코드는 **학습 목적** 이다.
프로덕션에서는 검증된 라이브러리를 써야 한다.
직접 구현한 인증 코드는 거의 항상 취약하며, 이 저장소의 목적은 그 라이브러리들이 무엇을 대신 해주고 있는지 이해하는 것이다.
