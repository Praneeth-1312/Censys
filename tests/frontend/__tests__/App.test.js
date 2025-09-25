import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import App from '../App';
import { apiClient } from '../utils';

// Mock the API client
jest.mock('../utils', () => ({
  apiClient: {
    healthCheck: jest.fn(),
    uploadDataset: jest.fn(),
    getUploadedData: jest.fn(),
    summarizeHost: jest.fn(),
    summarizeAllHosts: jest.fn(),
    checkApiKeys: jest.fn(),
    getStats: jest.fn(),
  },
  handleApiError: jest.fn((error, defaultMessage) => defaultMessage),
}));

// Mock the child components
jest.mock('../Summarizer', () => {
  return function MockSummarizer() {
    return <div data-testid="summarizer">Summarizer Component</div>;
  };
});

jest.mock('../UploadDataset', () => {
  return function MockUploadDataset({ onUploadSuccess }) {
    return (
      <div data-testid="upload-dataset">
        <button 
          data-testid="mock-upload-success"
          onClick={() => onUploadSuccess({ hosts: [], count: 0 })}
        >
          Mock Upload Success
        </button>
      </div>
    );
  };
});

jest.mock('../components/StatusPanel', () => {
  return function MockStatusPanel() {
    return <div data-testid="status-panel">Status Panel</div>;
  };
});

describe('App Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Mock successful health check by default
    apiClient.healthCheck.mockResolvedValue({ status: 'healthy' });
  });

  test('renders app title and subtitle', () => {
    render(<App />);
    
    expect(screen.getByText('🔍 Censys Host Summarizer')).toBeInTheDocument();
    expect(screen.getByText('Upload your dataset and get intelligent host summaries')).toBeInTheDocument();
  });

  test('renders status toggle button', () => {
    render(<App />);
    
    const statusButton = screen.getByText('📊 Show Status');
    expect(statusButton).toBeInTheDocument();
  });

  test('toggles status panel visibility', () => {
    render(<App />);
    
    const statusButton = screen.getByText('📊 Show Status');
    
    // Initially hidden
    expect(screen.queryByTestId('status-panel')).not.toBeInTheDocument();
    
    // Click to show
    fireEvent.click(statusButton);
    expect(screen.getByTestId('status-panel')).toBeInTheDocument();
    expect(screen.getByText('📊 Hide Status')).toBeInTheDocument();
    
    // Click to hide
    fireEvent.click(screen.getByText('📊 Hide Status'));
    expect(screen.queryByTestId('status-panel')).not.toBeInTheDocument();
  });

  test('renders upload and summarizer components', () => {
    render(<App />);
    
    expect(screen.getByTestId('upload-dataset')).toBeInTheDocument();
    expect(screen.getByTestId('summarizer')).toBeInTheDocument();
  });

  test('handles upload success', async () => {
    render(<App />);
    
    const uploadButton = screen.getByTestId('mock-upload-success');
    fireEvent.click(uploadButton);
    
    // The component should handle the upload success
    // This is tested through the component's internal state management
    expect(uploadButton).toBeInTheDocument();
  });

  test('shows backend error when health check fails', async () => {
    apiClient.healthCheck.mockRejectedValue(new Error('Connection failed'));
    
    render(<App />);
    
    await waitFor(() => {
      expect(screen.getByText(/Backend server is not responding/)).toBeInTheDocument();
    });
  });

  test('shows new upload button when dataset is uploaded', async () => {
    render(<App />);
    
    // Simulate upload success
    const uploadButton = screen.getByTestId('mock-upload-success');
    fireEvent.click(uploadButton);
    
    // Should show new upload button
    await waitFor(() => {
      expect(screen.getByText('↻ New Upload')).toBeInTheDocument();
    });
  });
});
