.PHONY: test test-routers test-redis test-polar test-conformance vet verify verify-commit

# Go applies this deadline to the entire package. The three-engine SQL race
# suite can exceed 30 minutes on a hosted runner. The workflow has a 60-minute limit.
test:
	go test -race -count=1 -timeout=45m ./...

test-routers:
	cd integrations/routers && go test -race -count=1 ./...

test-redis:
	cd adapters/redis && go test -race -count=1 ./...

test-polar:
	cd integrations/polar && go test -race -count=1 ./...

test-conformance:
	npm --prefix conformance ci --ignore-scripts --no-audit --no-fund
	npm --prefix conformance test

vet:
	@test -z "$$(gofmt -l .)" || { echo "Run gofmt -w on:"; gofmt -l .; exit 1; }
	go vet ./...
	cd integrations/routers && go vet ./...
	cd adapters/redis && go vet ./...
	cd integrations/polar && go vet ./...

verify: test test-routers test-redis test-polar vet test-conformance

# Run from the files a clean clone will receive, including the nested Go modules.
verify-commit:
	@set -eu; \
	snapshot=$$(mktemp -d); \
	trap 'rm -rf "$$snapshot"' EXIT; \
	git archive --format=tar --output="$$snapshot/source.tar" HEAD; \
	tar -xf "$$snapshot/source.tar" -C "$$snapshot"; \
	$(MAKE) -C "$$snapshot" verify
