import { apiClient, handleApiError, validateFile } from '../../../frontend/src/utils';
import { MESSAGES } from '../../../frontend/src/constants';

// Mock axios
jest.mock('axios');
import axios from 'axios';

describe('API Client', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('uploadDataset', () => {
    test('uploads dataset successfully', async () => {
      const mockResponse = { data: { status: 'success', hosts_loaded: 5 } };
      axios.post.mockResolvedValue(mockResponse);

      const file = new File(['{"hosts": []}'], 'test.json', { type: 'application/json' });
      const result = await apiClient.uploadDataset(file);

      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/upload_dataset/'),
        expect.any(FormData),
        expect.objectContaining({
          headers: { 'Content-Type': 'multipart/form-data' },
          timeout: 30000,
        })
      );
      expect(result).toEqual(mockResponse.data);
    });

    test('handles upload error', async () => {
      const error = new Error('Upload failed');
      axios.post.mockRejectedValue(error);

      const file = new File(['{"hosts": []}'], 'test.json', { type: 'application/json' });
      
      await expect(apiClient.uploadDataset(file)).rejects.toThrow('Upload failed');
    });
  });

  describe('getUploadedData', () => {
    test('fetches uploaded data successfully', async () => {
      const mockResponse = { data: { hosts: [], count: 0 } };
      axios.get.mockResolvedValue(mockResponse);

      const result = await apiClient.getUploadedData();

      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/get_uploaded_data/'),
        expect.objectContaining({ timeout: 10000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('summarizeHost', () => {
    test('summarizes host successfully', async () => {
      const mockResponse = { 
        data: { 
          ip: '192.168.1.1', 
          summary: 'Test summary',
          risk_level: 'Medium'
        } 
      };
      axios.post.mockResolvedValue(mockResponse);

      const result = await apiClient.summarizeHost('192.168.1.1');

      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/summarize_host/'),
        { ip: '192.168.1.1' },
        expect.objectContaining({ timeout: 60000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('summarizeAllHosts', () => {
    test('summarizes all hosts successfully', async () => {
      const mockResponse = { 
        data: { 
          summaries: [{ ip: '192.168.1.1', summary: 'Test summary' }],
          total_hosts: 1,
          processing_time: 2.5
        } 
      };
      axios.get.mockResolvedValue(mockResponse);

      const result = await apiClient.summarizeAllHosts();

      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/summarize_all/'),
        expect.objectContaining({ timeout: 300000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('healthCheck', () => {
    test('checks health successfully', async () => {
      const mockResponse = { data: { status: 'healthy', hosts_loaded: 5 } };
      axios.get.mockResolvedValue(mockResponse);

      const result = await apiClient.healthCheck();

      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/health'),
        expect.objectContaining({ timeout: 5000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('checkApiKeys', () => {
    test('checks API keys successfully', async () => {
      const mockResponse = { 
        data: { 
          GEMINI_API_KEY: true, 
          OPENAI_API_KEY: false,
          has_any_key: true
        } 
      };
      axios.get.mockResolvedValue(mockResponse);

      const result = await apiClient.checkApiKeys();

      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/check_key/'),
        expect.objectContaining({ timeout: 5000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });

  describe('getStats', () => {
    test('gets stats successfully', async () => {
      const mockResponse = { 
        data: { 
          total_hosts: 10,
          risk_distribution: { High: 2, Medium: 5, Low: 3 },
          avg_services_per_host: 3.2
        } 
      };
      axios.get.mockResolvedValue(mockResponse);

      const result = await apiClient.getStats();

      expect(axios.get).toHaveBeenCalledWith(
        expect.stringContaining('/stats/'),
        expect.objectContaining({ timeout: 10000 })
      );
      expect(result).toEqual(mockResponse.data);
    });
  });
});

describe('Error Handling', () => {
  describe('handleApiError', () => {
    test('handles timeout error', () => {
      const error = { code: 'ECONNABORTED' };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Request timeout - please try again');
    });

    test('handles network error', () => {
      const error = { code: 'NETWORK_ERROR' };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Network error - please check your connection');
    });

    test('handles response with detail', () => {
      const error = { 
        response: { 
          data: { detail: 'Specific error message' } 
        } 
      };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Specific error message');
    });

    test('handles response with error field', () => {
      const error = { 
        response: { 
          data: { error: 'Error field message' } 
        } 
      };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Error field message');
    });

    test('handles 404 error', () => {
      const error = { response: { status: 404 } };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Resource not found');
    });

    test('handles 500 error', () => {
      const error = { response: { status: 500 } };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Server error - please try again later');
    });

    test('handles error message', () => {
      const error = { message: 'Error message' };
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Error message');
    });

    test('returns default message for unknown error', () => {
      const error = {};
      const result = handleApiError(error, 'Default error');
      expect(result).toBe('Default error');
    });
  });
});

describe('File Validation', () => {
  describe('validateFile', () => {
    test('validates valid JSON file', () => {
      const file = new File(['{"test": "data"}'], 'test.json', { type: 'application/json' });
      const result = validateFile(file);
      expect(result.isValid).toBe(true);
    });

    test('rejects null file', () => {
      const result = validateFile(null);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe(MESSAGES.UPLOAD.SELECT_FILE);
    });

    test('rejects non-JSON file', () => {
      const file = new File(['not json'], 'test.txt', { type: 'text/plain' });
      const result = validateFile(file);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('Please select a valid JSON file.');
    });

    test('rejects empty file', () => {
      const file = new File([''], 'test.json', { type: 'application/json' });
      const result = validateFile(file);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe('File is empty.');
    });
  });
});
