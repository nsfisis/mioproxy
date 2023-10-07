.PHONY: all
all: build

.PHONY: build
build:
	go build .

.PHONY: fmt
fmt:
	go fmt .

.PHONY: clean
clean:
	rm -f ./mioproxy
