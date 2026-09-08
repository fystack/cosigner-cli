VERSION ?= dev
COMMIT ?= dev
OUT ?= dist
LDFLAGS = -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test dist
build:
	go build -trimpath -ldflags='$(LDFLAGS)' -o $(OUT)/cosigner-cli ./cmd/cosigner-cli
test:
	go vet ./...
	go test -race ./...
dist:
	mkdir -p $(OUT)
	set -e; for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags='$(LDFLAGS)' -o $(OUT)/cosigner-cli-$$os-$$arch ./cmd/cosigner-cli; \
	done
