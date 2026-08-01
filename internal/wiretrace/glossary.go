package wiretrace

// glossary maps OAuth 2.0 / OIDC parameter and claim names to a one-line
// explanation of why the parameter exists at all.
//
// The point of chapter 00 is to look at a real login and ask "why is this
// parameter here". Anything missing from this map is rendered as a TODO in the
// generated trace so the gap is visible instead of silently skipped.
var glossary = map[string]string{
	// --- authorization request ---
	"response_type":         "무엇을 돌려받을지. code = Authorization Code flow",
	"client_id":             "누가 요청하는 클라이언트인지",
	"redirect_uri":          "인가 결과를 돌려받을 주소. IdP에 사전 등록된 값과 정확히 일치해야 함",
	"scope":                 "요청에서는 요구하는 범위, 응답에서는 실제 허용된 범위. 둘이 다를 수 있다. openid가 있어야 OIDC가 된다",
	"state":                 "CSRF 방어. 내가 시작한 요청인지 콜백에서 대조",
	"nonce":                 "리플레이 방어. ID 토큰 안의 nonce와 대조",
	"code_challenge":        "PKCE. code_verifier의 해시. 인가 요청 시점에 미리 커밋",
	"code_challenge_method": "PKCE 해시 방식. S256만 써야 함 (plain은 방어가 안 됨)",
	"prompt":                "로그인 화면을 강제/생략할지 (none, login, consent)",
	"max_age":               "마지막 인증으로부터 허용할 최대 경과 시간(초)",
	"login_hint":            "로그인 폼에 미리 채울 사용자 식별자",
	"ui_locales":            "로그인 화면 언어",
	"acr_values":            "요구하는 인증 강도 (step-up 인증)",
	"id_token_hint":         "이전에 받은 ID 토큰. 로그아웃/재인증 시 누구인지 알려줌",
	"response_mode":         "인가 응답 전달 방식 (query, fragment, form_post)",
	"resource":              "이 토큰을 쓸 대상 리소스 서버 (RFC 8707)",
	"audience":              "발급될 토큰의 aud로 넣어달라는 요청 (Keycloak 방언)",

	// --- authorization response ---
	"code":              "인가 코드. 단발성이고 수명이 짧다. 이걸로 토큰과 교환",
	"session_state":     "IdP 세션 식별자 (OIDC Session Management)",
	"iss":               "이 응답/토큰을 발행한 IdP. 콜백에 실려오면 mix-up 방어용 (RFC 9207)",
	"error":             "에러 코드",
	"error_description": "사람이 읽는 에러 설명. 민감 정보가 새기 쉬운 자리",

	// --- token request ---
	"grant_type":            "무슨 방식으로 토큰을 받을지. authorization_code / refresh_token / ...",
	"code_verifier":         "PKCE. 인가 요청 때 커밋한 challenge의 원본. 여기서 처음 노출된다",
	"client_secret":         "클라이언트 인증. 백채널에서만 오갈 수 있다",
	"client_assertion":      "private_key_jwt 방식의 클라이언트 인증 (secret 대신 서명된 JWT)",
	"client_assertion_type": "client_assertion의 형식",
	"refresh_token":         "액세스 토큰 갱신용. 액세스 토큰보다 훨씬 오래 산다",
	"subject_token":         "Token Exchange. 교환하려는 원본 토큰 (RFC 8693)",
	"subject_token_type":    "Token Exchange. 원본 토큰의 종류",
	"requested_token_type":  "Token Exchange. 받고 싶은 토큰의 종류",
	"actor_token":           "Token Exchange. 대신 행동하는 주체의 토큰",

	// --- token response ---
	"access_token":       "리소스 서버에 제시할 토큰. 리소스 서버가 audience",
	"id_token":           "인증 결과. 클라이언트 본인이 audience. 리소스 서버에 보내면 안 됨",
	"token_type":         "토큰 제시 방식. Bearer = 가진 사람이 곧 주인",
	"expires_in":         "액세스 토큰 남은 수명(초)",
	"refresh_expires_in": "리프레시 토큰 남은 수명(초). Keycloak 확장",
	"not-before-policy":  "이 시각 이전 발급 토큰은 무효 (Keycloak 확장)",

	// --- token claims (payload) ---
	"sub":       "사용자의 안정적 식별자. email과 달리 바뀌지 않는다",
	"aud":       "이 토큰을 받아야 할 대상. 없으면 리소스 서버는 무엇으로 자기 것인지 판단하나?",
	"exp":       "만료 시각",
	"iat":       "발급 시각",
	"nbf":       "이 시각 전에는 무효",
	"auth_time": "실제로 사용자가 인증한 시각. iat과 다를 수 있다 (SSO 재사용)",
	"azp":       "이 토큰을 받기로 한 당사자. aud가 없거나 여러 개일 때 누가 주인공인지",
	"sid":       "세션 식별자. back-channel logout에서 어느 세션을 죽일지 특정",
	"at_hash":   "액세스 토큰의 해시. 프론트채널로 받은 액세스 토큰의 무결성 확인용",
	"typ":       "페이로드의 typ은 Keycloak 확장. ID / Bearer / Refresh 를 구분한다 (헤더의 typ과 다른 것)",
	"jti":       "토큰 고유 ID. 리플레이 감지/블랙리스트용",
	"acr":       "실제로 수행된 인증 강도",
	"amr":       "사용된 인증 수단 (pwd, otp, ...)",
	"act":       "위임 체인. 지금 누가 대신 행동 중인지 (RFC 8693)",
	"cnf":       "토큰이 묶인 키. sender-constrained token (DPoP/mTLS)",

	// --- profile / email scope claims (OIDC Core 5.1) ---
	"name":               "표시용 전체 이름. profile scope",
	"given_name":         "이름. profile scope",
	"family_name":        "성. profile scope",
	"preferred_username": "사람이 읽는 사용자명. **바뀔 수 있다.** 식별자로 쓰면 안 되고 sub를 써야 한다",
	"email":              "email scope. 이것도 바뀔 수 있다",
	"email_verified":     "IdP가 이메일 소유를 확인했는지. false면 이메일로 계정을 매칭하면 안 된다",
	"allowed-origins":    "이 클라이언트에 허용된 CORS origin. Keycloak 확장이고 표준 클레임이 아니다",
}

// headerGlossary covers the JOSE header, which is a different namespace from
// the payload. `typ` means media type here and something else entirely as a
// Keycloak payload claim, so the two must not share one entry.
var headerGlossary = map[string]string{
	"alg":  "서명 알고리즘. **검증할 때 이 값을 믿으면 안 된다**",
	"kid":  "어느 공개키로 서명했는지. JWKS에서 키를 고르는 데 씀",
	"typ":  "미디어 타입 (RFC 7519 §5.1). 보통 JWT. 페이로드의 typ 클레임과 다른 것",
	"cty":  "중첩 JWT일 때 안쪽 콘텐츠 타입",
	"jku":  "키를 가져올 URL. **공격자가 지정할 수 있으면 그대로 뚫린다**",
	"x5t":  "서명에 쓴 X.509 인증서의 지문",
	"crit": "반드시 이해해야 하는 확장 헤더 목록. 모르면 거부해야 한다",
}

const todo = "**TODO** 이 값은 왜 있나?"

// describe returns the payload/parameter glossary entry, or a TODO marker.
func describe(name string) string {
	if s, ok := glossary[name]; ok {
		return s
	}
	return todo
}

// describeHeader returns the JOSE header glossary entry, or a TODO marker.
func describeHeader(name string) string {
	if s, ok := headerGlossary[name]; ok {
		return s
	}
	return todo
}
