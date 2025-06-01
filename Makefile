# Makefile for rate limiter SDK

.PHONY: help test test-race test-cover build clean lint fmt vet mod-tidy examples benchmark docs

# Default target
help: ## Show this help message
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $1, $2}' $(MAKEFILE_LIST)

# Testing
test: ## Run tests
	go test -v ./...

test-race: ## Run tests with race detector
	go test -race -v ./...

test-cover: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-cover-html: test-cover ## Generate HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Building
build: ## Build the project
	go build ./...

# Code quality
lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed, run: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$(go env GOPATH)/bin v1.54.2" && exit 1)
	golangci-lint run

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

mod-tidy: ## Tidy go modules
	go mod tidy

# Benchmarking
benchmark: ## Run benchmarks
	go test -bench=. -benchmem ./...

benchmark-cpu: ## Run CPU benchmarks
	go test -bench=. -benchmem -cpuprofile=cpu.prof ./...

benchmark-mem: ## Run memory benchmarks
	go test -bench=. -benchmem -memprofile=mem.prof ./...

# Examples
examples: ## Run all examples
	@echo "Running basic example..."
	cd examples/basic && go run .
	@echo "Running production example..."
	cd examples/production && go run .
	@echo "Running comparison example..."
	cd examples/comparison && go run .

examples-basic: ## Run basic example
	cd examples/basic && go run .

examples-production: ## Run production example
	cd examples/production && go run .

examples-comparison: ## Run comparison example
	cd examples/comparison && go run .

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	go doc -all ./middleware > docs/api.md
	@echo "Documentation generated in docs/api.md"

docs-serve: ## Serve documentation locally
	godoc -http=:6060
	@echo "Documentation server running at http://localhost:6060"

# Cleaning
clean: ## Clean build artifacts and caches
	go clean -cache
	go clean -testcache
	go clean -modcache
	rm -f coverage.out coverage.html
	rm -f cpu.prof mem.prof
	rm -f *.test

# Development workflow
dev-setup: ## Set up development environment
	go mod download
	@echo "Installing development tools..."
	@which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

ci: mod-tidy check test-race benchmark ## CI pipeline (used in GitHub Actions)

# Release helpers
version: ## Show current version from git tag
	@git describe --tags --abbrev=0 2>/dev/null || echo "No version tags found"

tag: ## Create a new version tag (usage: make tag VERSION=v1.0.0)
	@if [ -z "$(VERSION)" ]; then echo "Usage: make tag VERSION=v1.0.0"; exit 1; fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)

# Monitoring and profiling
profile-cpu: ## Profile CPU usage
	go test -bench=. -cpuprofile=cpu.prof ./...
	go tool pprof cpu.prof

profile-mem: ## Profile memory usage
	go test -bench=. -memprofile=mem.prof ./...
	go tool pprof mem.prof

# Docker support (optional)
docker-build: ## Build Docker image
	docker build -t rate-limiter-sdk .

docker-test: ## Run tests in Docker
	docker run --rm -v $(PWD):/app -w /app golang:1.21 make test

# Security
security: ## Run security checks
	@which gosec > /dev/null || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	gosec ./...

# Performance testing
load-test: ## Run load tests (requires examples to be running)
	@echo "Make sure examples are running first..."
	@echo "Testing basic rate limiter..."
	ab -n 1000 -c 10 http://localhost:8080/api/v1/ping || echo "ab (Apache Bench) not installed"

stress-test: ## Run stress tests
	go test -run=XXX -bench=. -benchtime=30s ./...

# Development utilities
watch: ## Watch for file changes and run tests
	@which air > /dev/null || go install github.com/cosmtrek/air@latest
	air

install-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/cosmtrek/air@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Package and distribution
package: clean ## Package the SDK
	mkdir -p dist
	tar -czf dist/rate-limiter-sdk.tar.gz --exclude=dist --exclude=.git .
	@echo "Package created: dist/rate-limiter-sdk.tar.gz"

# All-in-one commands
all: clean dev-setup check benchmark docs ## Run everything
quick: fmt vet test ## Quick development check