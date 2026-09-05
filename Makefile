CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf

all: generate build

generate:
	@echo "==> Generating eBPF Go bindings..."
	cd userspace/cmd && go generate ./...

build: generate
	@echo "==> Building GhostGate daemon..."
	go build -o bin/ghostgate userspace/cmd/main.go userspace/cmd/ghostgate_bpf.go

run: build
	@echo "==> Running GhostGate (requires root for XDP)..."
	sudo ./bin/ghostgate -iface eth0

clean:
	rm -rf bin/
	rm -f userspace/cmd/ghostgate_bpf.go userspace/cmd/ghostgate_bpf.o