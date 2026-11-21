.PHONY: test test-routers test-conformance vet verify

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
