OAPI := go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1
# sqlc runs from the locally installed binary; go run sqlc fails to compile pg_query_go cgo on macOS Xcode 16+
SQLC := sqlc
MIGRATE := go run -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.1
COMPOSE := docker compose -f ../omnisurg-infrastructure/compose/docker-compose.local.yml --env-file ../omnisurg-infrastructure/.env
INFRA := ../omnisurg-infrastructure

.PHONY: help generate generate-check lint test build run migrate-up migrate-down migrate-create docs seed-dev compose-up compose-down smoke grpc-smoke ci

help:
	@echo "make generate        - oapi-codegen + sqlc into internal/generated and internal/db (committed)"
	@echo "make generate-check  - generate then fail on any git diff in generated dirs or the spec"
	@echo "make lint            - golangci-lint plus OpenAPI lint"
	@echo "make test            - go test -race ./..."
	@echo "make build           - compile the server binary"
	@echo "make run             - run the server against the local stack (requires .env)"
	@echo "make migrate-up      - apply migrations to OMNISURG_DATABASE_URL"
	@echo "make migrate-create name=<short> - scaffold a new migration pair"
	@echo "make compose-up      - bring up the local stack and wait for the service health endpoint"
	@echo "make smoke           - run the Contract Smoke Test against the local service"
	@echo "make ci              - lint + generate-check + test + build + smoke (the local CI gate)"

generate:
	$(OAPI) -config oapi-codegen.yaml docs/api-contract/openapi.yaml
	$(SQLC) generate

generate-check: generate
	@if [ -n "$$(git status --porcelain internal/generated internal/db docs/api-contract/openapi.yaml)" ]; then \
		echo "Generated code or spec is out of sync. Run make generate and commit." >&2; \
		git status --porcelain internal/generated internal/db docs/api-contract/openapi.yaml; \
		exit 1; \
	fi

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8 run ./...
	@if command -v redocly >/dev/null 2>&1; then \
		redocly lint --config docs/api-contract/.redocly.yaml docs/api-contract/openapi.yaml; \
	elif command -v npx >/dev/null 2>&1; then \
		npx -y @redocly/cli@1.25.15 lint --config docs/api-contract/.redocly.yaml docs/api-contract/openapi.yaml; \
	else \
		echo "redocly and npx both unavailable, skipping OpenAPI lint"; \
	fi

test:
	go test -race -count=1 ./...

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/server ./cmd/server

run:
	go run ./cmd/server

migrate-up:
	$(MIGRATE) -path migrations -database "$$OMNISURG_DATABASE_URL&x-migrations-table=identity_schema_migrations" up

migrate-down:
	$(MIGRATE) -path migrations -database "$$OMNISURG_DATABASE_URL&x-migrations-table=identity_schema_migrations" down 1

migrate-create:
	$(MIGRATE) create -ext sql -dir migrations -seq $(name)

seed-dev:
	go run ./cmd/seed

# compose-up brings up the shared local dependencies (postgres, redis, etc),
# applies migrations, seeds the CST users, then starts the service on the host
# in the background and waits for the health endpoint. The service runs on the
# host in P1 because the shared libraries are not yet published to GitHub.
compose-up:
	$(MAKE) -C $(INFRA) up
	$(MAKE) build
	set -a; . ./.env; set +a; \
	  $(MIGRATE) -path migrations -database "$$OMNISURG_DATABASE_URL&x-migrations-table=identity_schema_migrations" up; \
	  go run ./cmd/seed && \
	  ( ./bin/server > /tmp/identity-server.log 2>&1 & echo $$! > /tmp/identity-server.pid ); \
	  for i in 1 2 3 4 5 6 7 8 9 10; do \
	    sleep 2; \
	    if curl -sf http://localhost:8081/api/v1/identity/health > /dev/null; then echo "identity-service healthy"; exit 0; fi; \
	  done; \
	  echo "identity-service did not become healthy in 20 seconds" >&2; cat /tmp/identity-server.log; exit 1

compose-down:
	@[ -f /tmp/identity-server.pid ] && kill "$$(cat /tmp/identity-server.pid)" 2>/dev/null && rm -f /tmp/identity-server.pid || true

smoke: compose-up
	( cd smoke && go run ./cmd -credentials credentials.json -spec ../docs/api-contract/openapi.yaml ) && \
	  $(MAKE) grpc-smoke; \
	  status=$$?; $(MAKE) compose-down; exit $$status

# grpc-smoke is a lightweight gRPC probe: it checks the health RPC on the shared
# grpc.Server (which now also serves the identity business RPCs). It runs against
# the already-running local service (started by compose-up). It gracefully skips
# when grpcurl is not installed; the authoritative business RPC gate is the Go
# integration test in internal/grpcserver.
grpc-smoke:
	set -a; . ./.env; set +a; \
	  if command -v grpcurl >/dev/null 2>&1; then \
	    echo "gRPC health probe on :$$OMNISURG_GRPC_PORT"; \
	    grpcurl -plaintext localhost:$$OMNISURG_GRPC_PORT grpc.health.v1.Health/Check; \
	  else \
	    echo "grpcurl not installed, skipping gRPC probe (Go integration test in internal/grpcserver is the authoritative gRPC gate)"; \
	  fi

ci: lint generate-check test build smoke
