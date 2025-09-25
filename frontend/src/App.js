import React, { useState, useCallback } from "react";
import Summarizer from "./Summarizer";
import UploadDataset from "./UploadDataset";
import { UI_CONSTANTS } from "./constants";

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

  const appStyles = {
    minHeight: "100vh",
    background: `linear-gradient(135deg, #667eea 0%, #764ba2 100%)`,
    padding: UI_CONSTANTS.SPACING.XL,
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
  };

  const containerStyles = {
    maxWidth: "1200px",
    margin: "0 auto",
    backgroundColor: "white",
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.XL,
    boxShadow: UI_CONSTANTS.SHADOWS.LG,
    overflow: "hidden"
  };

  const headerStyles = {
    background: `linear-gradient(135deg, ${UI_CONSTANTS.COLORS.PRIMARY} 0%, ${UI_CONSTANTS.COLORS.PRIMARY_DARK} 100%)`,
    color: "white",
    padding: `${UI_CONSTANTS.SPACING.XXXL} ${UI_CONSTANTS.SPACING.XXXXL}`,
    textAlign: "center"
  };

  const titleStyles = {
    margin: "0",
    fontSize: "2.5rem",
    fontWeight: "700",
    letterSpacing: "-0.025em"
  };

  const subtitleStyles = {
    margin: `${UI_CONSTANTS.SPACING.SM} 0 0 0`,
    fontSize: "1.1rem",
    opacity: "0.9",
    fontWeight: "300"
  };

  const mainContentStyles = {
    padding: UI_CONSTANTS.SPACING.XXXXL
  };

  const uploadSectionStyles = {
    marginBottom: UI_CONSTANTS.SPACING.XXXXL,
    background: UI_CONSTANTS.COLORS.GRAY[50],
    border: `2px solid ${UI_CONSTANTS.COLORS.GRAY[200]}`,
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.LG,
    padding: UI_CONSTANTS.SPACING.XXL,
    transition: "all 0.3s ease"
  };

  const uploadHeaderStyles = {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: UI_CONSTANTS.SPACING.LG
  };

  const uploadTitleStyles = {
    margin: "0",
    fontSize: "1.5rem",
    fontWeight: "600",
    color: UI_CONSTANTS.COLORS.GRAY[800],
    display: "flex",
    alignItems: "center",
    gap: UI_CONSTANTS.SPACING.SM
  };

  const uploadDescriptionStyles = {
    margin: `${UI_CONSTANTS.SPACING.XS} 0 0 0`,
    fontSize: "0.9rem",
    color: UI_CONSTANTS.COLORS.GRAY[500]
  };

  const newUploadButtonStyles = {
    background: `linear-gradient(135deg, ${UI_CONSTANTS.COLORS.ERROR} 0%, ${UI_CONSTANTS.COLORS.ERROR_DARK} 100%)`,
    color: "white",
    border: "none",
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.MD,
    padding: `${UI_CONSTANTS.SPACING.SM} ${UI_CONSTANTS.SPACING.MD}`,
    cursor: "pointer",
    fontSize: "14px",
    fontWeight: "500",
    display: "flex",
    alignItems: "center",
    gap: UI_CONSTANTS.SPACING.XS,
    transition: "all 0.2s ease",
    boxShadow: `0 2px 4px rgba(239, 68, 68, 0.3)`
  };

  return (
    <div className="App" style={appStyles}>
      <div style={containerStyles}>
        {/* Header */}
        <div style={headerStyles}>
          <h1 style={titleStyles}>
            🔍 Censys Host Summarizer
          </h1>
          <p style={subtitleStyles}>
            Upload your dataset and get intelligent host summaries
          </p>
        </div>

        {/* Main Content */}
        <div style={mainContentStyles}>
          {/* Upload Section */}
          <div style={uploadSectionStyles}>
            <div style={uploadHeaderStyles}>
              <div>
                <h3 style={uploadTitleStyles}>
                  📁 Upload JSON Dataset
                </h3>
                <p style={uploadDescriptionStyles}>
                  Select a JSON file containing host data
                </p>
              </div>
              {datasetUploaded && (
                <button
                  onClick={handleCancelUpload}
                  style={newUploadButtonStyles}
                  onMouseOver={(e) => {
                    e.target.style.transform = "translateY(-1px)";
                    e.target.style.boxShadow = "0 4px 8px rgba(239, 68, 68, 0.4)";
                  }}
                  onMouseOut={(e) => {
                    e.target.style.transform = "translateY(0)";
                    e.target.style.boxShadow = "0 2px 4px rgba(239, 68, 68, 0.3)";
                  }}
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
