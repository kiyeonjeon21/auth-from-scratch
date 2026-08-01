ISSUER ?= http://localhost:8080/realms/demo

.PHONY: help kc-up kc-down kc-reset kc-logs kc-export discovery run-00 tidy check

help: ## 사용 가능한 타깃
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

kc-up: ## Keycloak 기동 후 디스커버리 응답까지 대기
	docker compose up -d
	@printf "waiting for %s" "$(ISSUER)"
	@for i in $$(seq 1 60); do \
		if curl -fsS "$(ISSUER)/.well-known/openid-configuration" >/dev/null 2>&1; then \
			echo " ready"; exit 0; fi; \
		printf "."; sleep 2; \
	done; \
	echo " timeout"; docker compose logs --tail=40 keycloak; exit 1

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

run-00: ## 00-first-login-trace 실행
	go run ./00-first-login-trace -issuer "$(ISSUER)"

tidy: ## go mod tidy
	go mod tidy

check: ## vet + build
	go vet ./...
	go build ./...
