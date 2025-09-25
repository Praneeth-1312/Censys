import React, { useState, useCallback } from "react";
import Summarizer from "./Summarizer";
import UploadDataset from "./UploadDataset";
import "./App.css";

function App() {
  const [datasetUploaded, setDatasetUploaded] = useState(false);
  const [uploadedData, setUploadedData] = useState(null);
  const [summarizerKey, setSummarizerKey] = useState(0);
  const [uploadResetKey, setUploadResetKey] = useState(0);

  const handleUploadAttempt = useCallback(() => {
    // Clear previous data when user explicitly starts new upload
    setDatasetUploaded(false);
    setUploadedData(null);
    // Force Summarizer to reset by changing its key
    setSummarizerKey(prev => prev + 1);
    // Force Upload component to reset by changing its key
    setUploadResetKey(prev => prev + 1);
  }, []);

  const handleUploadSuccess = useCallback((data) => {
    setDatasetUploaded(true);
    setUploadedData(data);
    // Reset summarizer to work with new dataset
    setSummarizerKey(prev => prev + 1);
  }, []);

  const handleCancelUpload = useCallback(() => {
    setDatasetUploaded(false);
    setUploadedData(null);
    // Force Summarizer to reset by changing its key
    setSummarizerKey(prev => prev + 1);
    // Force Upload component to reset by changing its key
    setUploadResetKey(prev => prev + 1);
  }, []);

  return (
    <div className="app">
      <div className="app-container">
        {/* Header */}
        <div className="app-header">
          <h1 className="app-title">
            🔍 Censys Host Summarizer
          </h1>
          <p className="app-subtitle">
            Upload your dataset and get intelligent host summaries
          </p>
        </div>

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

          {/* Summarizer Section - Always visible */}
          <Summarizer key={summarizerKey} />
        </div>
      </div>
    </div>
  );
}

export default App;
