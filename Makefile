# Hakscan Makefile
GOCMD=go
BINARY=hakscan
CMD=./cmd/hakscan

.PHONY: build install test vet tidy run clean

build:
	$(GOCMD) build -trimpath -ldflags="-s -w" -o $(BINARY) $(CMD)

install:
	$(GOCMD) install $(CMD)

test:
	$(GOCMD) test ./...

vet:
	$(GOCMD) vet ./...

tidy:
	$(GOCMD) mod tidy

run:
	$(GOCMD) run $(CMD) $(ARGS)

clean:
	rm -f $(BINARY)
	rm -rf dist
