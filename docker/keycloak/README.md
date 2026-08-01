# 로컬 IdP (Keycloak)

## Realm as code

`realm-demo.json`이 유일한 소스다.
`--import-realm`으로 기동할 때마다 이 파일에서 realm이 만들어진다.

**관리 콘솔에서 클릭으로 설정하지 않는다.**
다음 `make kc-reset` 때 전부 날아간다.
콘솔에서 실험을 했고 그걸 남기고 싶으면 파일로 되받는다.

```bash
make kc-export > /tmp/demo.json   # 확인 후 realm-demo.json에 반영
```

## 지금 들어있는 것

| 종류 | 이름 | 용도 |
|---|---|---|
| realm | `demo` | 전 챕터 공용. `master`는 관리용이라 쓰지 않는다 |
| client | `demo-client` | confidential. Authorization Code + PKCE. 00, 02 |
| client | `demo-api` | 리소스 서버. 토큰의 `aud`가 될 대상. 03 |
| user | `alice` / `alice` | 테스트 사용자 |

`demo-client`의 시크릿은 `demo-client-secret`이다.
로컬 전용 고정값이고, 진짜 시크릿을 여기 넣지 않는다.

## 버전과 feature flag

`docker-compose.yml`에서 `26.2`로 핀 고정되어 있다.
**`latest`로 바꾸지 않는다.** feature flag 이름이 릴리스마다 움직인다.

지금 켜둔 preview 기능:

| flag | 왜 |
|---|---|
| `token-exchange-standard:v2` | 06. 표준 RFC 8693 token exchange |
| `dpop:v1` | 08. sender-constrained token |

버전을 올릴 때는 flag 이름이 그대로인지 먼저 확인한다.

```bash
docker run --rm quay.io/keycloak/keycloak:<버전> build --help-all | grep -A2 'token-exchange'
```

26.2 기준으로 `token-exchange`는 레거시(v1), 표준 방식은 `token-exchange-standard`(v2)다.
이름이 헷갈리기 쉬우니 06에서 401/501이 뜨면 여기부터 본다.

## 자주 걸리는 것

**`redirect_uri` 불일치**
`realm-demo.json`의 `redirectUris`와 앱의 `-listen` 포트가 어긋난 것이다.
파일을 고치고 `make kc-reset`.

**임포트가 통째로 실패**
realm JSON에 Keycloak이 모르는 키가 있으면 기동 자체가 실패한다.
주석용 `_comment` 같은 키도 거부한다.
`make kc-logs`에서 `Unrecognized field`를 찾는다.

**변경이 반영 안 됨**
`make kc-up`은 이미 있는 볼륨을 그대로 쓴다.
realm 파일을 고쳤으면 `make kc-reset`(볼륨 삭제 후 재임포트)이어야 한다.
