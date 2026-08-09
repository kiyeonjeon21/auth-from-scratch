# 02. 답변

스펙 문장을 옮겨 적지 않는다.
자기 말로 쓰고, 못 쓰겠으면 아직 모르는 것이다.
`trace.md`의 몇 번 왕복인지, 또는 어느 파일 어느 함수인지 근거를 같이 적는다.

---

### `state`와 `nonce`는 각각 무엇을 막나? 왜 하나로 합칠 수 없나?

> (미작성)

### PKCE는 원래 모바일 앱을 위한 것이었는데 왜 지금은 웹 앱에도 필수인가?

> (미작성)

### Implicit flow는 왜 폐기됐나?

> (미작성)

### 디스커버리 문서 안의 `issuer`를, 내가 요청한 issuer와 대조해야 하는 이유는?

> (미작성) 근거: `oidc.go` 의 `fetchDiscovery`

### `code_verifier`는 왜 43자 이상이어야 하나? 짧으면 무엇이 뚫리나?

> (미작성) 근거: `oidc.go` 의 `newVerifier`

### `aud`가 배열일 때 `azp`를 추가로 봐야 하는 이유는?

> (미작성) 근거: `idtoken.go` 의 `validateIDToken`

### 토큰 교환 요청에 `redirect_uri`를 왜 또 보내나?

> (미작성) 근거: `oidc.go` 의 `exchangeCode`

### `client_secret_basic`과 `client_secret_post`의 실제 차이는?

> (미작성) 근거: 두 방식으로 각각 실행한 트레이스의 토큰 요청

---

## 00과의 diff에서 발견한 것

`make diff-traces` 결과 중 설명할 수 있는 차이와, 아직 설명 못 하는 차이를 나눠 적는다.

| 차이 | 왜 생겼나 |
|---|---|
| | |

---

## 아직 안 한 것

- **서명 검증** — 03에서. 이게 없으면 위 검증들이 전부 무의미해지는 이유를 적어둘 것
- **공격 재현 2건** — `state` 제거, `redirect_uri` 와일드카드
- **`private_key_jwt`** — 01에서 JWT 서명을 손으로 해본 뒤에
