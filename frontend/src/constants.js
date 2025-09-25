// API Configuration
export const API_BASE_URL = 'http://127.0.0.1:8000';

// API Endpoints
export const API_ENDPOINTS = {
  UPLOAD_DATASET: `${API_BASE_URL}/upload_dataset/`,
  GET_UPLOADED_DATA: `${API_BASE_URL}/get_uploaded_data/`,
  SUMMARIZE_HOST: `${API_BASE_URL}/summarize_host/`,
  SUMMARIZE_ALL: `${API_BASE_URL}/summarize_all/`,
  HEALTH_CHECK: `${API_BASE_URL}/health`,
  CHECK_KEY: `${API_BASE_URL}/check_key/`,
  STATS: `${API_BASE_URL}/stats/`,
};

// UI Constants
export const UI_CONSTANTS = {
  COLORS: {
    PRIMARY: '#4f46e5',
    PRIMARY_DARK: '#7c3aed',
    SUCCESS: '#10b981',
    SUCCESS_DARK: '#059669',
    ERROR: '#ef4444',
    ERROR_DARK: '#dc2626',
    WARNING: '#f59e0b',
    INFO: '#3b82f6',
    INFO_DARK: '#1d4ed8',
    GRAY: {
      50: '#f8fafc',
      100: '#f1f5f9',
      200: '#e2e8f0',
      300: '#cbd5e1',
      400: '#94a3b8',
      500: '#64748b',
      600: '#475569',
      700: '#334155',
      800: '#1e293b',
      900: '#0f172a',
    }
  },
  SPACING: {
    XS: '4px',
    SM: '8px',
    MD: '12px',
    LG: '16px',
    XL: '20px',
    XXL: '24px',
    XXXL: '32px',
    XXXXL: '40px',
  },
  BORDER_RADIUS: {
    SM: '4px',
    MD: '8px',
    LG: '12px',
    XL: '16px',
  },
  SHADOWS: {
    SM: '0 1px 3px rgba(0,0,0,0.1)',
    MD: '0 4px 12px rgba(0,0,0,0.15)',
    LG: '0 20px 40px rgba(0,0,0,0.1)',
  }
};

// Component Messages
export const MESSAGES = {
  UPLOAD: {
    SELECT_FILE: 'Please select a JSON file.',
    SUCCESS: (count) => `✅ Dataset uploaded successfully: ${count} hosts loaded`,
    ERROR: '❌ Error uploading dataset',
    NO_FILE: 'Select File First',
    UPLOAD_BUTTON: '📤 Upload',
  },
  SUMMARIZER: {
    NO_DATASET_TITLE: 'Host Summarization Ready',
    NO_DATASET_MESSAGE: 'Upload a JSON dataset above to enable host summarization features',
    RESET_MESSAGE: '🔄 Summarizer reset - ready for new dataset',
    INDIVIDUAL_TITLE: 'Summarize Individual Host',
    INDIVIDUAL_DESCRIPTION: 'Enter a specific IP address to get detailed analysis',
    BATCH_TITLE: 'Summarize All Hosts',
    BATCH_DESCRIPTION: 'Generate comprehensive summaries for all hosts in the dataset',
    ANALYZING: '⏳ Analyzing...',
    SUMMARIZE_BUTTON: '🚀 Summarize',
    PROCESSING_ALL: '⏳ Processing All Hosts...',
    SUMMARIZE_ALL_BUTTON: '🚀 Summarize All Hosts',
    ANALYSIS_SUMMARY: '📋 Analysis Summary',
    BATCH_RESULTS: '📈 Batch Analysis Results',
  },
  ERRORS: {
    HOST_NOT_FOUND: 'Host not found',
    NO_DATASET: 'No dataset uploaded',
    FETCH_ERROR: 'Error fetching summary.',
    FETCH_ALL_ERROR: 'Error fetching summaries for all hosts.',
  }
};

// Validation
export const VALIDATION = {
  FILE_TYPES: ['.json'],
  MIN_FILE_SIZE: 0,
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
};
