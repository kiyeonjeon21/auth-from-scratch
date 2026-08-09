# 능력 지도 — 완성품(Keycloak)이 할 수 있는 것

이 파일은 `00-reference-tour`가 자동 생성한다. 직접 고치지 않는다.

돌아가는 실제 IdP가 **자기 입으로** 광고하는 능력을, `notes/comparison.md`의 표에 매핑한 것이다.
여기 있는 거의 모든 줄이 완성된 기능으로 이미 존재한다. 챕터는 그걸 하나씩 뜯는 작업이다.

아래 값은 라이브러리 없이 디스커버리 문서 하나를 GET해서 읽은 것이다. 그 자체가 이 저장소의 첫 교훈이다 — 엔드포인트를 하드코딩하지 않고 한 번의 요청으로 받아온다.

---

## 신뢰의 뿌리 — 무엇을 믿기로 하는가

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `issuer` | 이 IdP의 정체. 받은 토큰의 iss와 대조하는 기준 | 00·02에서 확인 |
| `jwks_uri` | 서명 검증용 공개키 목록. 표 1 '신뢰의 뿌리'의 실물 | 03에서 뜯음 (kid 선택) |

## 표 1. 로그인 방식 (OIDC 흐름)

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `authorization_endpoint` | 브라우저를 보내는 곳. Authorization Code 흐름의 시작 | 완료 (00·02) |
| `token_endpoint` | code를 토큰으로 바꾸는 백채널 | 완료 (00·02) |
| `userinfo_endpoint` | 액세스 토큰으로 사용자 정보를 받는 곳 | 완료 (00) |
| `code_challenge_methods_supported`<br><small>plain, S256</small> | PKCE 방식. S256이 있어야 안전 | 완료 (02에서 직접 계산) |

## 표 1·4. 토큰을 받는 방법들

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `grant_types_supported`<br><small>authorization_code, client_credentials, implicit, password, refresh_token, urn:ietf:params…</small> | 토큰을 받는 방법들. code / refresh / client_credentials / token-exchange ... | code=완료, token-exchange=lab |

## 표 2. 클라이언트 인증 (토큰·요청 보호)

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `token_endpoint_auth_methods_supported`<br><small>private_key_jwt, client_secret_basic, client_secret_post, tls_client_auth, client_secret_j…</small> | 클라이언트 인증 방식. secret / private_key_jwt / mTLS | secret=완료(02), private_key_jwt=01 후, mTLS=미착수 |

## 표 2. DPoP — 토큰을 키에 묶기

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `dpop_signing_alg_values_supported`<br><small>PS384, ES384, RS384, ES256, RS256, ES512, PS256, PS512, RS512</small> | DPoP 지원. 토큰을 클라이언트 키에 묶는다 | 미착수 (서버는 준비됨) |

## 표 1·2. 검증 방식

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `introspection_endpoint` | 불투명 토큰을 IdP에 물어 검증. 로컬 검증의 반대편 | 03에서 로컬 검증과 대조 |

## 표 1. 취소

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `revocation_endpoint` | 토큰을 즉시 무효화. bearer의 '취소 어려움'을 부분적으로 푼다 | 04에서 |

## 표 3 / 로그아웃

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `end_session_endpoint` | RP-Initiated Logout. 로그아웃의 시작점 | 05에서 뜯음 |

## 표 3. SSO 전파

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `frontchannel_logout_supported`<br><small>true</small> | iframe로 각 RP에 로그아웃 전파 | 05 |
| `backchannel_logout_supported`<br><small>true</small> | IdP가 각 RP에 logout token을 POST | 05 |

## 표 3. SSO 세션

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `check_session_iframe` | 세션이 살아있는지 브라우저에서 확인 (Session Management) | 05 |

## 인증 강도 (NIST AAL)

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `acr_values_supported`<br><small>0, 1</small> | 인증 강도 요청. 재인증·step-up의 재료 | 05·MFA에서 |

## 지도의 가장자리 — 이 IdP는 하지만 이 저장소 범위 밖

| IdP가 광고하는 것 | 의미 | 어디서 뜯나 |
|---|---|---|
| `device_authorization_endpoint` | 입력장치 없는 기기용 흐름 (TV 로그인) | 범위 밖 |
| `backchannel_authentication_endpoint` | CIBA. 다른 기기로 승인받는 흐름 | 범위 밖 |
| `registration_endpoint` | 클라이언트를 동적으로 등록 (RFC 7591) | 범위 밖 |
| `pushed_authorization_request_endpoint` | 인가 요청을 백채널로 미리 보냄 (PAR) | 범위 밖 |

## 아직 지도에 없음

이 IdP가 광고하지만 위에서 다루지 않은 것들이다. 대부분 세부 알고리즘 목록이나 확장 기능이다.
파고들 만한 게 보이면 여기서 시작한다.

- `authorization_encryption_alg_values_supported`
- `authorization_encryption_enc_values_supported`
- `authorization_response_iss_parameter_supported`
- `authorization_signing_alg_values_supported`
- `backchannel_authentication_request_signing_alg_values_supported`
- `backchannel_logout_session_supported`
- `backchannel_token_delivery_modes_supported`
- `claim_types_supported`
- `claims_parameter_supported`
- `claims_supported`
- `frontchannel_logout_session_supported`
- `id_token_encryption_alg_values_supported`
- `id_token_encryption_enc_values_supported`
- `id_token_signing_alg_values_supported`
- `introspection_endpoint_auth_methods_supported`
- `introspection_endpoint_auth_signing_alg_values_supported`
- `prompt_values_supported`
- `request_object_encryption_alg_values_supported`
- `request_object_encryption_enc_values_supported`
- `request_object_signing_alg_values_supported`
- `request_parameter_supported`
- `request_uri_parameter_supported`
- `response_modes_supported`
- `response_types_supported`
- `revocation_endpoint_auth_methods_supported`
- `revocation_endpoint_auth_signing_alg_values_supported`
- `scopes_supported`
- `subject_types_supported`
- `token_endpoint_auth_signing_alg_values_supported`
- `userinfo_encryption_alg_values_supported`
- `userinfo_encryption_enc_values_supported`
- `userinfo_signing_alg_values_supported`

---

## 그래서 다음

이 지도의 각 줄이 `notes/comparison.md`의 한 칸이 된다.
'어디서 뜯나' 열이 챕터 순서다. 완성품을 먼저 봤으니, 이제 하나씩 내려가며 손으로 재현하고 diff한다.
