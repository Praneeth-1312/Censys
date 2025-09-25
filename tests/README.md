# Testing Directory

This directory contains all testing-related files for the Censys Host Summarizer project, organized by type and scope.

## Directory Structure

```
tests/
├── backend/           # Backend unit and integration tests
│   └── test_main.py   # FastAPI application tests
├── frontend/          # Frontend unit tests
│   └── __tests__/     # React component and utility tests
├── e2e/              # End-to-end tests
│   ├── tests/        # Playwright E2E test files
│   ├── playwright.config.js  # Playwright configuration
│   └── package.json  # E2E test dependencies
├── data/             # Test data and fixtures
│   ├── sample_hosts.json  # Sample host data for testing
│   └── invalid.txt   # Invalid test files
└── README.md         # This file
```

## Running Tests

### From Project Root (Recommended)
```bash
# Run all tests
tests/run-all-tests.bat  # Windows
tests/run-all-tests.sh   # Unix/Linux/Mac

# Or run the simple version
tests/run-tests-simple.bat  # Windows
```

### From Tests Directory
```bash
# Navigate to tests directory
cd tests

# Run all tests from here
.\run-tests-from-here.bat  # Windows PowerShell
run-tests-from-here.bat    # Windows Command Prompt
```

### Individual Test Suites

#### Backend Tests
```bash
# Option 1: From tests/backend directory
cd tests/backend
.\run-backend-tests.bat  # Windows PowerShell
run-backend-tests.bat    # Windows Command Prompt

# Option 2: From project root
cd backend
pytest ../tests/backend/test_main.py -v
```

#### Frontend Tests
```bash
# Option 1: From tests/frontend directory
cd tests/frontend
.\run-frontend-tests.bat  # Windows PowerShell
run-frontend-tests.bat    # Windows Command Prompt

# Option 2: From project root
cd frontend
npm test -- --coverage --watchAll=false
```

#### End-to-End Tests
```bash
# Option 1: From tests/e2e directory
cd tests/e2e
.\run-e2e-tests.bat  # Windows PowerShell
run-e2e-tests.bat    # Windows Command Prompt

# Option 2: From project root
cd tests/e2e
npm install
npm test
```

## Test Data

The `data/` directory contains:
- **sample_hosts.json**: Realistic host data for testing upload and analysis functionality
- **invalid.txt**: Invalid file for testing error handling

## Test Coverage

### Backend Tests
- ✅ API endpoint testing
- ✅ Data validation and parsing
- ✅ Error handling scenarios
- ✅ File upload functionality
- ✅ Host summarization logic
- ✅ Risk assessment algorithms

### Frontend Tests
- ✅ Component rendering
- ✅ User interactions
- ✅ API integration
- ✅ Error handling
- ✅ State management

### E2E Tests
- ✅ Complete user workflows
- ✅ File upload and processing
- ✅ Individual host analysis
- ✅ Batch processing
- ✅ Error scenarios
- ✅ Responsive design

## Adding New Tests

### Backend Tests
1. Add new test functions to `tests/backend/test_main.py`
2. Follow the existing naming convention: `test_<function_name>`
3. Use pytest fixtures for setup and teardown
4. Mock external dependencies (AI services, file system)

### Frontend Tests
1. Create new test files in `tests/frontend/__tests__/`
2. Use React Testing Library for component testing
3. Mock API calls and external dependencies
4. Test user interactions and state changes

### E2E Tests
1. Add new test files to `tests/e2e/tests/`
2. Use Playwright for browser automation
3. Test complete user journeys
4. Include both positive and negative test cases

## Test Configuration

### Backend
- Uses pytest with async support
- Includes coverage reporting
- Mocks external AI services
- Tests with realistic data

### Frontend
- Uses Jest and React Testing Library
- Includes coverage reporting
- Mocks API calls
- Tests component behavior

### E2E
- Uses Playwright for cross-browser testing
- Includes mobile viewport testing
- Tests with real browser interactions
- Includes accessibility testing

## Continuous Integration

Tests are designed to run in CI/CD pipelines:
- Backend tests run in Python environment
- Frontend tests run in Node.js environment
- E2E tests require both backend and frontend to be running
- All tests include proper cleanup and isolation
