# Cerberus SIEM Makefile
.PHONY: all build run clean swagger test help

# Default target
all: swagger build

# Build the application
build:
	@echo Building Cerberus SIEM...
	go build -o cerberus.exe .

# Generate Swagger documentation
swagger:
	@echo Generating Swagger documentation...
	swag init -g api/api.go --output docs --parseDependency --parseInternal

# Format Swagger annotations
swagger-fmt:
	@echo Formatting Swagger annotations...
	swag fmt -g api/api.go

# Run the application
run: all
	@echo Starting Cerberus SIEM...
	./cerberus.exe

# Run tests
test:
	@echo Running tests...
	go test -v ./...

# Run tests with race detection
test-race:
	@echo Running tests with race detection...
	go test -race -v ./...

# Run tests with coverage
test-coverage:
	@echo Running tests with coverage...
	go test -cover ./...

# Clean build artifacts
clean:
	@echo Cleaning build artifacts...
	rm -f cerberus.exe
	rm -rf docs/

# Install dependencies
deps:
	@echo Installing dependencies...
	go mod download
	go mod tidy

# Install development tools
dev-tools:
	@echo Installing development tools...
	go install github.com/swaggo/swag/cmd/swag@v1.16.6

# Lint the code
lint:
	@echo Running linters...
	go vet ./...
	go fmt ./...

# Help target
help:
	@echo Cerberus SIEM Build Commands:
	@echo   make all          - Generate swagger docs and build
	@echo   make build        - Build the application
	@echo   make swagger      - Generate Swagger documentation
	@echo   make swagger-fmt  - Format Swagger annotations
	@echo   make run          - Build and run the application
	@echo   make test         - Run unit tests
	@echo   make test-race    - Run tests with race detection
	@echo   make test-coverage - Run tests with coverage
	@echo   make clean        - Remove build artifacts and docs
	@echo   make deps         - Download and tidy dependencies
	@echo   make dev-tools    - Install development tools
	@echo   make lint         - Run code linters and formatters
	@echo   make help         - Show this help message
