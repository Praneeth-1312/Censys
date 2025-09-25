#!/bin/bash

# Comprehensive Test Runner for Censys Host Summarizer
# This script runs all tests from the centralized tests directory

set -e

echo "🧪 Running all tests for Censys Host Summarizer..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to run tests and report results
run_test() {
    local test_name="$1"
    local test_command="$2"
    local test_dir="$3"
    
    echo -e "\n${BLUE}Running $test_name...${NC}"
    cd "$test_dir"
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ $test_name passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
}

# Track overall success
overall_success=true

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${YELLOW}Project root: $PROJECT_ROOT${NC}"

# Run backend tests
echo -e "\n${YELLOW}=== Backend Tests ===${NC}"
if ! run_test "Backend Unit & Integration Tests" "cd backend && source venv/bin/activate && python -m pytest ../tests/backend/test_main.py -v --tb=short" "$PROJECT_ROOT"; then
    overall_success=false
fi

# Run frontend tests
echo -e "\n${YELLOW}=== Frontend Tests ===${NC}"
if ! run_test "Frontend Component Tests" "cd frontend && npm test -- --coverage --watchAll=false --passWithNoTests" "$PROJECT_ROOT"; then
    overall_success=false
fi

# Check if services are running for E2E tests
echo -e "\n${YELLOW}=== E2E Tests ===${NC}"
echo -e "${BLUE}Checking if services are running for E2E tests...${NC}"

# Check if backend is running
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend is running on http://localhost:8000"
    
    # Check if frontend is running
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo "✅ Frontend is running on http://localhost:3000"
        
        # Run E2E tests
        if ! run_test "End-to-End Tests" "cd tests/e2e && npm install && npm test" "$PROJECT_ROOT"; then
            overall_success=false
        fi
    else
        echo -e "${YELLOW}⚠️  Frontend is not running on http://localhost:3000${NC}"
        echo -e "${BLUE}To run E2E tests, start the frontend with: cd frontend && npm start${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Backend is not running on http://localhost:8000${NC}"
    echo -e "${BLUE}To run E2E tests, start the backend with: cd backend && source venv/bin/activate && python -m uvicorn main:app --reload --port 8000${NC}"
fi

# Return to project root
cd "$PROJECT_ROOT"

# Report overall results
echo -e "\n${YELLOW}=== Test Summary ===${NC}"
if [ "$overall_success" = true ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    echo -e "${GREEN}✅ Backend tests: PASSED${NC}"
    echo -e "${GREEN}✅ Frontend tests: PASSED${NC}"
    if curl -s http://localhost:8000/health > /dev/null 2>&1 && curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo -e "${GREEN}✅ E2E tests: PASSED${NC}"
    else
        echo -e "${YELLOW}⚠️  E2E tests: SKIPPED (services not running)${NC}"
    fi
    exit 0
else
    echo -e "${RED}💥 Some tests failed. Check the output above for details.${NC}"
    echo -e "${RED}❌ Check the test output above to identify which tests failed${NC}"
    exit 1
fi

