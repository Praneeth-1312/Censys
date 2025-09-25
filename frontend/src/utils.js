import axios from 'axios';
import { API_ENDPOINTS, MESSAGES } from './constants';

// API Utility Functions
export const apiClient = {
  uploadDataset: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await axios.post(API_ENDPOINTS.UPLOAD_DATASET, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    
    return response.data;
  },

  getUploadedData: async () => {
    const response = await axios.get(API_ENDPOINTS.GET_UPLOADED_DATA);
    return response.data;
  },

  summarizeHost: async (ip) => {
    const response = await axios.post(API_ENDPOINTS.SUMMARIZE_HOST, { ip });
    return response.data;
  },

  summarizeAllHosts: async () => {
    const response = await axios.get(API_ENDPOINTS.SUMMARIZE_ALL);
    return response.data;
  },
};

// Error Handling Utilities
export const handleApiError = (error, defaultMessage) => {
  console.error('API Error:', error);
  
  if (error.response?.data?.detail) {
    return error.response.data.detail;
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
