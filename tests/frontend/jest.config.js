module.exports = {
  // Test environment
  testEnvironment: 'jsdom',
  
  // Setup files
  setupFilesAfterEnv: ['<rootDir>/setupTests.js'],
  
  // Module name mapping for absolute imports
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/../../frontend/src/$1',
  },
  
  // Test file patterns
  testMatch: [
    '<rootDir>/__tests__/**/*.test.js',
    '<rootDir>/__tests__/**/*.test.jsx',
    '<rootDir>/__tests__/**/*.spec.js',
    '<rootDir>/__tests__/**/*.spec.jsx',
  ],
  
  // Coverage configuration
  collectCoverage: true,
  coverageDirectory: '<rootDir>/../../coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  collectCoverageFrom: [
    '<rootDir>/../../frontend/src/**/*.{js,jsx}',
    '!<rootDir>/../../frontend/src/index.js',
    '!<rootDir>/../../frontend/src/reportWebVitals.js',
    '!<rootDir>/../../frontend/src/setupTests.js',
  ],
  
  // Transform configuration
  transform: {
    '^.+\\.(js|jsx)$': 'babel-jest',
  },
  
  // Module file extensions
  moduleFileExtensions: ['js', 'jsx', 'json'],
  
  // Clear mocks between tests
  clearMocks: true,
  
  // Verbose output
  verbose: true,
};

