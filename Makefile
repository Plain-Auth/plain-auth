.PHONY: test test-routers test-conformance vet verify verify-commit

test:
	go test -race -count=1 ./...

test-routers:
	cd integrations/routers && go test -race -count=1 ./...

test-conformance:
	npm --prefix conformance ci --ignore-scripts --no-audit --no-fund
	npm --prefix conformance test

vet:
	go vet ./...
	cd integrations/routers && go vet ./...

verify: test test-routers vet test-conformance

# Run from the files a clean clone will receive, including the nested Go module.
verify-commit:
	@set -eu; \
	snapshot=$$(mktemp -d); \
	trap 'rm -rf "$$snapshot"' EXIT; \
	git archive --format=tar --output="$$snapshot/source.tar" HEAD; \
	tar -xf "$$snapshot/source.tar" -C "$$snapshot"; \
	$(MAKE) -C "$$snapshot" verify
