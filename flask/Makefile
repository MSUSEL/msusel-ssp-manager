# Flask Application Test Makefile
# Provides convenient commands for running tests and development tasks

.PHONY: help test test-unit test-integration test-coverage test-fast clean build setup

# Default target
help:
    @echo "Flask Application Test Commands"
    @echo "==============================="
    @echo ""
    @echo "Testing:"
    @echo "  test              Run all tests"
    @echo "  test-unit         Run unit tests only"
    @echo "  test-integration  Run integration tests only"
    @echo "  test-coverage     Run tests with coverage report"
    @echo "  test-fast         Run tests excluding slow ones"
    @echo "  test-debug        Run tests in debug mode"
    @echo ""
    @echo "Development:"
    @echo "  build             Build Docker images"
    @echo "  setup             Setup development environment"
    @echo "  clean             Clean test artifacts"
    @echo "  lint              Run code linting"
    @echo ""
    @echo "CI/CD:"
    @echo "  ci-test           Run tests for CI/CD pipeline"
    @echo "  ci-coverage       Generate coverage for CI/CD"

# Test commands
test:
    @echo "Running all tests..."
    ./run_tests.sh -v

test-unit:
    @echo "Running unit tests..."
    ./run_tests.sh -v -m "unit"

test-integration:
    @echo "Running integration tests..."
    ./run_tests.sh -v -m "integration"

test-coverage:
    @echo "Running tests with coverage..."
    ./run_tests.sh -v -c

test-fast:
    @echo "Running fast tests (excluding slow ones)..."
    ./run_tests.sh -v -f

test-debug:
    @echo "Running tests in debug mode..."
    ./run_tests.sh --debug -v

# Specific test files
test-prepare:
    @echo "Running prepare project tests..."
    ./run_tests.sh -v -t test_prepare_project.py

test-runner:
    @echo "Running test runner tests..."
    ./run_tests.sh -v -t test_test_runner.py

test-inspec:
    @echo "Running InSpec tests..."
    ./run_tests.sh -v -t test_inspec_runner.py

# Development commands
build:
    @echo "Building Docker images..."
    docker compose build flask

setup:
    @echo "Setting up development environment..."
    chmod +x run_tests.sh
    mkdir -p test_results coverage_reports logs
    pip install -r requirements.txt

clean:
    @echo "Cleaning test artifacts..."
    ./run_tests.sh --clean
    rm -rf __pycache__ .pytest_cache
    rm -rf test_results/* coverage_reports/* logs/*
    docker system prune -f

lint:
    @echo "Running code linting..."
    flake8 app/ tests/ --max-line-length=120
    pylint app/ tests/ --disable=C0114,C0115,C0116

# CI/CD commands
ci-test:
    @echo "Running CI/CD tests..."
    ./run_tests.sh -v --no-cleanup

ci-coverage:
    @echo "Generating CI/CD coverage..."
    ./run_tests.sh -c -v --no-cleanup

# Docker commands
docker-test:
    @echo "Running tests in Docker environment..."
    docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

docker-clean:
    @echo "Cleaning Docker test environment..."
    docker compose -f docker-compose.test.yml down -v
    docker system prune -f

# Utility commands
logs:
    @echo "Showing test logs..."
    tail -f logs/test.log

watch:
    @echo "Watching for file changes and running tests..."
    find . -name "*.py" | entr -c make test-fast