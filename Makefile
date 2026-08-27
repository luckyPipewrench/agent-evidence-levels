# SPDX-License-Identifier: Apache-2.0

# AEL reference checker + fixture corpus.
# Stdlib-only Go. Cache dirs kept under $HOME (some hosts have a quota-full /tmp).

export GOFLAGS ?= -mod=mod
BIN := ./bin

.PHONY: build gen test check fmt clean brand check-brand

brand:
	@python3 scripts/render_brand.py
	@magick -background none assets/ael-logo.svg -resize 256x256 -strip -define png:exclude-chunks=date,time assets/ael-logo-256.png
	@magick -background none assets/social-preview.svg -resize 1280x640 -strip -define png:exclude-chunks=date,time assets/social-preview.png
	@python3 scripts/render_brand.py --stamp-png

check-brand:
	@python3 scripts/render_brand.py --check

build:
	@mkdir -p $(BIN)
	go build -o $(BIN)/aelcheck ./checker/cmd/aelcheck
	go build -o $(BIN)/aelgen   ./checker/cmd/aelgen
	go build -o $(BIN)/aelpackage ./checker/cmd/aelpackage

gen: build
	$(BIN)/aelgen --out ./fixtures

test:
	go test ./...

# The proof: regenerate the corpus, grade every case, assert it matches expect.json
# (rung corpus + governability extension corpus).
check: gen check-brand
	go test ./checker/conformance/... -v
	@echo
	@echo "=== human-readable corpus grading ==="
	go run ./checker/cmd/aelgen --report --out ./fixtures

fmt:
	gofumpt -w . 2>/dev/null || gofmt -w .

clean:
	rm -rf $(BIN)
