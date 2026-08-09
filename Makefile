ISSUER ?= http://localhost:8080/realms/demo
CLIENT_AUTH ?= client_secret_basic

# Local fixture admin, same values as docker-compose.yml.
KC_ADMIN ?= admin
KC_ADMIN_PW ?= admin

.PHONY: help kc-up kc-allow-http kc-down kc-reset kc-logs kc-export discovery run-tour run-00 run-02 run-03 run-04 attack-fixation diff-traces tidy check

help: ## 사용 가능한 타깃
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

kc-up: ## Keycloak 기동 후 디스커버리 응답까지 대기
	docker compose up -d
	@printf "waiting for keycloak"
	@for i in $$(seq 1 60); do \
		code=$$(curl -s -o /dev/null -w '%{http_code}' "$(ISSUER)/.well-known/openid-configuration" 2>/dev/null); \
		if [ "$$code" != "000" ]; then echo " up"; break; fi; \
		printf "."; sleep 2; \
	done
	@$(MAKE) --no-print-directory kc-allow-http
	@curl -fsS "$(ISSUER)/.well-known/openid-configuration" >/dev/null 2>&1 \
		&& echo "discovery ready" \
		|| { echo "discovery 실패"; docker compose logs --tail=40 keycloak; exit 1; }

kc-allow-http: ## master realm의 HTTPS 강제를 끈다 (로컬 전용)
	@# Docker Desktop이 요청 출발지를 사설 대역 밖 주소로 넘기면 Keycloak이
	@# 'HTTPS required' 403을 낸다. demo realm은 realm-demo.json에서 끄지만
	@# master는 파일로 임포트하지 않으므로 여기서 컨테이너 안에서 끈다.
	@docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials \
		--server http://127.0.0.1:8080 --realm master \
		--user "$(KC_ADMIN)" --password "$(KC_ADMIN_PW)" >/dev/null 2>&1 || true
	@docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh \
		update realms/master -s sslRequired=NONE >/dev/null 2>&1 || true

kc-down: ## Keycloak 정지
	docker compose down

kc-reset: ## 컨테이너와 데이터를 지우고 realm-demo.json에서 재임포트
	docker compose down -v
	$(MAKE) kc-up

kc-logs: ## Keycloak 로그 따라가기
	docker compose logs -f keycloak

kc-export: ## 콘솔에서 만진 realm을 파일로 되받기 (STDOUT)
	docker compose exec keycloak /opt/keycloak/bin/kc.sh export \
		--realm demo --users realm_file --file /tmp/demo.json >/dev/null
	docker compose exec keycloak cat /tmp/demo.json

discovery: ## 디스커버리 문서 출력
	@curl -fsS "$(ISSUER)/.well-known/openid-configuration" | jq

run-tour: ## 00-reference-tour: 완성품(IdP)의 능력을 지도로 (top-down 진입점)
	go run ./00-reference-tour -issuer "$(ISSUER)"

run-03: ## 03-session-cookie 실행 (IdP 불필요). 사이트 A 5557 / B 5558
	go run ./03-session-cookie $(SESSION_FLAGS)

attack-fixation: ## 03의 session fixation 공격 재현 (앱이 떠 있어야 함)
	@bash 03-session-cookie/attack-fixation.sh

run-04: ## 04-logout 실행. RP A 5560 / RP B 5561
	go run ./04-logout -issuer "$(ISSUER)"

run-00: ## 00-first-login-trace 실행
	go run ./00-first-login-trace -issuer "$(ISSUER)"

run-02: ## 02-authcode-pkce 실행 (00과 같은 포트라 동시에 못 띄운다)
	go run ./02-authcode-pkce -issuer "$(ISSUER)" -client-auth "$(CLIENT_AUTH)"

diff-traces: ## 00(라이브러리)과 02(손으로)의 실제 HTTP 왕복을 비교
	@test -f 00-first-login-trace/trace.md || { echo "00 트레이스가 없다: make run-00"; exit 1; }
	@test -f 02-authcode-pkce/trace.md     || { echo "02 트레이스가 없다: make run-02"; exit 1; }
	@# 해설 블록은 각 챕터가 저자 마음대로 쓴 주석이라 비교 대상이 아니다.
	@# 진짜 물어볼 것은 "네트워크로 오간 것이 무엇이 다른가" 하나뿐이다.
	@echo "== 백채널 호출 수 =="
	@for f in 00-first-login-trace 02-authcode-pkce; do \
		printf "  %-22s %s번\n" "$$f" \
			"$$(sed -n '/^## 한눈에 보기/,/^---/p' $$f/trace.md | grep -c 'back (서버 간)')"; \
	done
	@echo
	@# exch: 트레이스에서 실제 HTTP 왕복(front/back)의 이름만 뽑아 정렬한다.
	@exch() { \
		sed -n '/^## 한눈에 보기/,/^---/p' "$$1/trace.md" \
		| grep -E '^\| [0-9]+ .*\((서버 간|브라우저 경유)\)' \
		| cut -d'|' -f5 | sed 's/^ *//;s/ *$$//' | sort -u; }; \
	exch 00-first-login-trace > /tmp/afs-00.txt; \
	exch 02-authcode-pkce     > /tmp/afs-02.txt; \
	echo "== 00은 하는데 02는 안 하는 것 =="; \
	comm -23 /tmp/afs-00.txt /tmp/afs-02.txt | sed 's/^/  /' | grep . || echo "  (없음)"; \
	echo; \
	echo "== 02만 하는 것 =="; \
	comm -13 /tmp/afs-00.txt /tmp/afs-02.txt | sed 's/^/  /' | grep . || echo "  (없음)"; \
	rm -f /tmp/afs-00.txt /tmp/afs-02.txt

tidy: ## go mod tidy
	go mod tidy

check: ## vet + build
	go vet ./...
	go build ./...
