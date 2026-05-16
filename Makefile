TINYGO ?= tinygo

.PHONY: build build-std deploy dev clean

# Recommended: TinyGo produces a much smaller WASM binary
build:
	mkdir -p build
	go run github.com/syumai/workers/cmd/workers-assets-gen -mode=tinygo
	$(TINYGO) build -o build/app.wasm -target wasm -no-debug .

# Alternative: standard Go (binary will be ~10-15 MB)
build-std:
	mkdir -p build
	go run github.com/syumai/workers/cmd/workers-assets-gen -mode=go
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o build/app.wasm .
	du -h build/app.wasm

deploy: build
	wrangler deploy

dev: build
	wrangler dev

clean:
	rm -rf build
