# Cerberus SIEM Build Script for Windows PowerShell
# Usage: .\build.ps1 [command]
# Commands: all, build, swagger, swagger-fmt, run, test, test-race, test-coverage, clean, deps, dev-tools, lint, help

param(
    [Parameter(Position=0)]
    [string]$Command = "all"
)

function Show-Help {
    Write-Host "Cerberus SIEM Build Commands:" -ForegroundColor Cyan
    Write-Host "  .\build.ps1 all          - Generate swagger docs and build"
    Write-Host "  .\build.ps1 build        - Build the application"
    Write-Host "  .\build.ps1 swagger      - Generate Swagger documentation"
    Write-Host "  .\build.ps1 swagger-fmt  - Format Swagger annotations"
    Write-Host "  .\build.ps1 run          - Build and run the application"
    Write-Host "  .\build.ps1 test         - Run unit tests"
    Write-Host "  .\build.ps1 test-race    - Run tests with race detection"
    Write-Host "  .\build.ps1 test-coverage - Run tests with coverage"
    Write-Host "  .\build.ps1 clean        - Remove build artifacts and docs"
    Write-Host "  .\build.ps1 deps         - Download and tidy dependencies"
    Write-Host "  .\build.ps1 dev-tools    - Install development tools"
    Write-Host "  .\build.ps1 lint         - Run code linters and formatters"
    Write-Host "  .\build.ps1 help         - Show this help message"
}

function Build-App {
    Write-Host "Building Cerberus SIEM..." -ForegroundColor Green
    go build -o cerberus.exe .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Build successful!" -ForegroundColor Green
    } else {
        Write-Host "Build failed!" -ForegroundColor Red
        exit 1
    }
}

function Generate-Swagger {
    Write-Host "Generating Swagger documentation..." -ForegroundColor Green
    swag init -g api/api.go --output docs --parseDependency --parseInternal
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Swagger documentation generated successfully!" -ForegroundColor Green
    } else {
        Write-Host "Swagger generation failed!" -ForegroundColor Red
        exit 1
    }
}

function Format-Swagger {
    Write-Host "Formatting Swagger annotations..." -ForegroundColor Green
    swag fmt -g api/api.go
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Swagger annotations formatted successfully!" -ForegroundColor Green
    } else {
        Write-Host "Swagger formatting failed!" -ForegroundColor Red
        exit 1
    }
}

function Run-App {
    Generate-Swagger
    Build-App
    Write-Host "Starting Cerberus SIEM..." -ForegroundColor Green
    .\cerberus.exe
}

function Run-Tests {
    Write-Host "Running tests..." -ForegroundColor Green
    go test -v ./...
}

function Run-Tests-Race {
    Write-Host "Running tests with race detection..." -ForegroundColor Green
    go test -race -v ./...
}

function Run-Tests-Coverage {
    Write-Host "Running tests with coverage..." -ForegroundColor Green
    go test -cover ./...
}

function Clean-Build {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Green
    if (Test-Path cerberus.exe) {
        Remove-Item cerberus.exe
        Write-Host "Removed cerberus.exe"
    }
    if (Test-Path docs) {
        Remove-Item -Recurse -Force docs
        Write-Host "Removed docs directory"
    }
    Write-Host "Clean complete!" -ForegroundColor Green
}

function Install-Deps {
    Write-Host "Installing dependencies..." -ForegroundColor Green
    go mod download
    go mod tidy
    Write-Host "Dependencies installed!" -ForegroundColor Green
}

function Install-DevTools {
    Write-Host "Installing development tools..." -ForegroundColor Green
    go install github.com/swaggo/swag/cmd/swag@v1.16.6
    Write-Host "Development tools installed!" -ForegroundColor Green
}

function Run-Lint {
    Write-Host "Running linters..." -ForegroundColor Green
    go vet ./...
    go fmt ./...
    Write-Host "Linting complete!" -ForegroundColor Green
}

# Main switch
switch ($Command.ToLower()) {
    "all" {
        Generate-Swagger
        Build-App
    }
    "build" {
        Build-App
    }
    "swagger" {
        Generate-Swagger
    }
    "swagger-fmt" {
        Format-Swagger
    }
    "run" {
        Run-App
    }
    "test" {
        Run-Tests
    }
    "test-race" {
        Run-Tests-Race
    }
    "test-coverage" {
        Run-Tests-Coverage
    }
    "clean" {
        Clean-Build
    }
    "deps" {
        Install-Deps
    }
    "dev-tools" {
        Install-DevTools
    }
    "lint" {
        Run-Lint
    }
    "help" {
        Show-Help
    }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Show-Help
        exit 1
    }
}
