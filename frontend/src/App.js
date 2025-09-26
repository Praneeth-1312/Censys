import React, { useState, useCallback, useEffect } from "react";
import Summarizer from "./Summarizer";
import UploadDataset from "./UploadDataset";
import StatusPanel from "./components/StatusPanel";
import { apiClient, handleApiError } from "./utils";
import "./App.css";

function App() {
  const [datasetUploaded, setDatasetUploaded] = useState(false);
  const [uploadedData, setUploadedData] = useState(null);
  const [summarizerKey, setSummarizerKey] = useState(0);
  const [uploadResetKey, setUploadResetKey] = useState(0);
  const [statusPanelKey, setStatusPanelKey] = useState(0);
  const [backendError, setBackendError] = useState(null);
  const [showStatusPanel, setShowStatusPanel] = useState(false);

  const handleUploadAttempt = useCallback(async () => {
    // Clear previous data when user explicitly starts new upload
    setDatasetUploaded(false);
    setUploadedData(null);
    // Force Summarizer to reset by changing its key
    setSummarizerKey(prev => prev + 1);
    // Force Upload component to reset by changing its key
    setUploadResetKey(prev => prev + 1);
    // Force StatusPanel to reset by changing its key
    setStatusPanelKey(prev => prev + 1);
    
    // Clear backend data
    try {
      await apiClient.resetData();
    } catch (error) {
      console.warn('Failed to reset backend data:', error);
      // Don't show error to user as this is not critical
    }
  }, []);

  const handleUploadSuccess = useCallback((data) => {
    setDatasetUploaded(true);
    setUploadedData(data);
    // Reset summarizer to work with new dataset
    setSummarizerKey(prev => prev + 1);
  }, []);

  const handleCancelUpload = useCallback(async () => {
    setDatasetUploaded(false);
    setUploadedData(null);
    // Force Summarizer to reset by changing its key
    setSummarizerKey(prev => prev + 1);
    // Force Upload component to reset by changing its key
    setUploadResetKey(prev => prev + 1);
    // Force StatusPanel to reset by changing its key
    setStatusPanelKey(prev => prev + 1);
    
    // Clear backend data
    try {
      await apiClient.resetData();
    } catch (error) {
      console.warn('Failed to reset backend data:', error);
      // Don't show error to user as this is not critical
    }
  }, []);

  // Check backend health on app load
  useEffect(() => {
    const checkBackendHealth = async () => {
      try {
        await apiClient.healthCheck();
        setBackendError(null);
      } catch (error) {
        setBackendError(handleApiError(error, 'Backend server is not responding'));
      }
    };

    checkBackendHealth();
  }, []);

  return (
    <div className="app">
      <div className="app-container">
        {/* Header */}
        <div className="app-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
            <div>
              <h1 className="app-title">
                🔍 Censys Host Summarizer
              </h1>
              <p className="app-subtitle">
                Upload your dataset and get intelligent host summaries
              </p>
            </div>
            <button
              onClick={() => setShowStatusPanel(!showStatusPanel)}
              style={{
                padding: '8px 16px',
                background: 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
              onMouseOver={(e) => {
                e.target.style.transform = 'translateY(-1px)';
                e.target.style.boxShadow = '0 4px 12px rgba(107, 114, 128, 0.3)';
              }}
              onMouseOut={(e) => {
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = 'none';
              }}
            >
              {showStatusPanel ? '📊 Hide Status' : '📊 Show Status'}
            </button>
          </div>
        </div>

        {/* Backend Error Alert */}
        {backendError && (
          <div style={{
            margin: '16px 0',
            padding: '12px 16px',
            background: 'linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)',
            color: '#991b1b',
            borderRadius: '8px',
            border: '1px solid #fecaca',
            fontSize: '14px',
            fontWeight: '500'
          }}>
            ⚠️ {backendError}
          </div>
        )}

        {/* Status Panel */}
        {showStatusPanel && (
          <div style={{
            margin: '16px 0',
            background: 'white',
            border: '1px solid #e2e8f0',
            borderRadius: '12px',
            padding: '20px',
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
          }}>
            <StatusPanel key={statusPanelKey} />
          </div>
        )}

        {/* Main Content */}
        <div className="app-main-content">
          {/* Upload Section */}
          <div className="upload-section">
            <div className="upload-header">
              <div>
                <h3 className="upload-title">
                  📁 Upload JSON Dataset
                </h3>
                <p className="upload-description">
                  Select a JSON file containing host data
                </p>
              </div>
              {datasetUploaded && (
                <button
                  onClick={handleCancelUpload}
                  className="new-upload-button"
                  title="Upload new dataset"
                >
                  ↻ New Upload
                </button>
              )}
            </div>
            <UploadDataset 
              onUploadAttempt={handleUploadAttempt} 
              onUploadSuccess={handleUploadSuccess} 
              resetTrigger={uploadResetKey}
            />
          </div>

          {/* Summarizer Section - Only show when dataset is uploaded */}
          {datasetUploaded ? (
            <Summarizer key={summarizerKey} hasDataset={true} />
          ) : (
            <div style={{ 
              background: "linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%)",
              border: "2px dashed #cbd5e1", 
              borderRadius: "12px", 
              padding: "40px 24px", 
              textAlign: "center",
              transition: "all 0.3s ease"
            }}>
              <div style={{
                fontSize: "3rem",
                marginBottom: "16px"
              }}>📊</div>
              <h3 style={{
                margin: "0 0 8px 0",
                fontSize: "1.5rem",
                fontWeight: "600",
                color: "#475569"
              }}>
                Host Summarization Ready
              </h3>
              <p style={{ 
                color: "#64748b", 
                margin: "0",
                fontSize: "1rem",
                lineHeight: "1.5"
              }}>
                Upload a JSON dataset above to enable host summarization features
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
