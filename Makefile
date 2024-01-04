.DEFAULT_GOAL := help
.PHONY: all build run test clean help mocks


GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run

## This help screen
help:
	@printf "Available targets:\n\n"
	@awk '/^[a-zA-Z\-\_0-9%:\\]+/ { \
	helpMessage = match(lastLine, /^## (.*)/); \
	if (helpMessage) { \
	helpCommand = $$1; \
	helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
	gsub("\\\\", "", helpCommand); \
	gsub(":+$$", "", helpCommand); \
	printf "  \x1b[32;01m%-35s\x1b[0m %s\n", helpCommand, helpMessage; \
	} \
        } \
        { lastLine = $$0 }' $(MAKEFILE_LIST) | sort -u
	@printf "\n"

## generate mocks. 
mocks:
	@echo "Generating mocks"
	@ mockgen -package mocks -destination p2p/protocol/mocks/mockedQuaiP2PNode.go -source=p2p/protocol/interface.go QuaiP2PNode

## generate protobuf files
protogen:
	@echo "Generating protobuf files"
	@protoc --go_out=. --go_opt=paths=source_relative \
	./p2p/pb/*.proto 

## build the go-quai binary
go-quai:
	@echo "Building go-quai"
	$(GORUN) build/ci.go install ./cmd/go-quai
	@echo "Done building."
	@echo "Run \"$(GOBIN)/go-quai\" to launch go-quai."

run:
	@echo "Running go-quai"
	build/bin/go-quai start --local --slices "[0 0]"

