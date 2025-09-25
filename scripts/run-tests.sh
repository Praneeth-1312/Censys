#!/bin/bash

# Test Runner Script for Censys Host Summarizer

set -e

echo "🧪 Running all tests for Censys Host Summarizer..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests and report results
run_test() {
    local test_name="$1"
    local test_command="$2"
    local test_dir="$3"
    
    echo -e "\n${YELLOW}Running $test_name...${NC}"
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

# Run backend tests
if ! run_test "Backend Tests" "source venv/bin/activate && pytest ../../tests/backend/test_main.py -v" "backend"; then
    overall_success=false
fi

# Run frontend tests
if ! run_test "Frontend Tests" "npm test -- --coverage --watchAll=false" "frontend"; then
    overall_success=false
fi

# Run E2E tests (only if backend and frontend are running)
echo -e "\n${YELLOW}Checking if services are running for E2E tests...${NC}"

# Check if backend is running
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend is running"
    
    # Check if frontend is running
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo "✅ Frontend is running"
        
        # Run E2E tests
        if ! run_test "E2E Tests" "npm test" "tests/e2e"; then
            overall_success=false
        fi
    else
        echo -e "${YELLOW}⚠️  Frontend is not running. Skipping E2E tests.${NC}"
        echo "To run E2E tests, start the frontend with: cd frontend && npm start"
    fi
else
    echo -e "${YELLOW}⚠️  Backend is not running. Skipping E2E tests.${NC}"
    echo "To run E2E tests, start the backend with: cd backend && source venv/bin/activate && python -m uvicorn main:app --reload --port 8000"
fi

# Return to project root
cd ..

# Report overall results
echo -e "\n${YELLOW}Test Summary:${NC}"
if [ "$overall_success" = true ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}💥 Some tests failed. Check the output above for details.${NC}"
    exit 1
fi
