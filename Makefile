.DEFAULT_GOAL := help

.PHONY: test
test: ## Test
	@go test ./... -race -bench . -benchmem -trimpath -cover

.PHONY: lint
lint: ## Lint
	@go get golang.org/x/tools/cmd/goimports@5916a50
	@go get github.com/instrumenta/kubeval@0.14.0
	@for d in $(shell go list -f {{.Dir}} ./...); do $(shell go env GOPATH)/bin/goimports -w $$d/*.go; done
	@docker run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v1.21.0 golangci-lint run --fix

.PHONY: dev
dev: ## Run skaffold
	@skaffold dev

.PHONY: help
help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
