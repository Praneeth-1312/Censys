import axios from 'axios';
import { API_ENDPOINTS, MESSAGES } from './constants';

// API Utility Functions
export const apiClient = {
  uploadDataset: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await axios.post(API_ENDPOINTS.UPLOAD_DATASET, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 30000, // 30 second timeout for file uploads
    });
    
    return response.data;
  },

  getUploadedData: async () => {
    const response = await axios.get(API_ENDPOINTS.GET_UPLOADED_DATA, {
      timeout: 10000,
    });
    return response.data;
  },

  summarizeHost: async (ip) => {
    const response = await axios.post(API_ENDPOINTS.SUMMARIZE_HOST, { ip }, {
      timeout: 60000, // 60 second timeout for AI processing
    });
    return response.data;
  },

  summarizeAllHosts: async () => {
    const response = await axios.get(API_ENDPOINTS.SUMMARIZE_ALL, {
      timeout: 300000, // 5 minute timeout for batch processing
    });
    return response.data;
  },

  healthCheck: async () => {
    const response = await axios.get(API_ENDPOINTS.HEALTH_CHECK, {
      timeout: 5000,
    });
    return response.data;
  },

  checkApiKeys: async () => {
    const response = await axios.get(API_ENDPOINTS.CHECK_KEY, {
      timeout: 5000,
    });
    return response.data;
  },

  getStats: async () => {
    const response = await axios.get(API_ENDPOINTS.STATS, {
      timeout: 10000,
    });
    return response.data;
  },
};

// Error Handling Utilities
export const handleApiError = (error, defaultMessage) => {
  console.error('API Error:', error);
  
  // Handle network errors
  if (error.code === 'ECONNABORTED') {
    return 'Request timeout - please try again';
  }
  
  if (error.code === 'NETWORK_ERROR' || !error.response) {
    return 'Network error - please check your connection';
  }
  
  // Handle HTTP errors
  if (error.response?.data?.detail) {
    return error.response.data.detail;
  }
  
  if (error.response?.data?.error) {
    return error.response.data.error;
  }
  
  if (error.response?.status === 404) {
    return 'Resource not found';
  }
  
  if (error.response?.status === 500) {
    return 'Server error - please try again later';
  }
  
  if (error.message) {
    return error.message;
  }
  
  return defaultMessage;
};

// File Validation
export const validateFile = (file) => {
  if (!file) {
    return { isValid: false, error: MESSAGES.UPLOAD.SELECT_FILE };
  }

  if (!file.name.toLowerCase().endsWith('.json')) {
    return { isValid: false, error: 'Please select a valid JSON file.' };
  }

  if (file.size === 0) {
    return { isValid: false, error: 'File is empty.' };
  }

  return { isValid: true };
};

// UI Utility Functions
export const createGradientStyle = (color1, color2, direction = '135deg') => ({
  background: `linear-gradient(${direction}, ${color1} 0%, ${color2} 100%)`,
});

export const createHoverEffect = (baseShadow, hoverShadow) => ({
  onMouseOver: (e) => {
    e.target.style.transform = 'translateY(-1px)';
    e.target.style.boxShadow = hoverShadow;
  },
  onMouseOut: (e) => {
    e.target.style.transform = 'translateY(0)';
    e.target.style.boxShadow = baseShadow;
  },
});

// Debounce utility for input handling
export const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};
