import React, { useState, useRef, useEffect, useCallback } from "react";
import { apiClient, handleApiError, validateFile } from "./utils";
import { MESSAGES } from "./constants";
import "./UploadDataset.css";

const UploadDataset = ({ onUploadAttempt, onUploadSuccess, resetTrigger }) => {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [isUploaded, setIsUploaded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const fileInputRef = useRef(null);

  // Reset file input when resetTrigger changes
  useEffect(() => {
    if (resetTrigger > 0) {
      setFile(null);
      setMessage("");
      setIsUploaded(false);
      setIsLoading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  }, [resetTrigger]);

  const handleFileChange = useCallback((e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
    setMessage("");
    setIsUploaded(false);
    // Don't clear previous data when selecting a file - only clear when upload succeeds
  }, []);

  const handleUpload = useCallback(async () => {
    const validation = validateFile(file);
    if (!validation.isValid) {
      setMessage(validation.error);
      return;
    }

    setIsLoading(true);

    try {
      const response = await apiClient.uploadDataset(file);
      setMessage(MESSAGES.UPLOAD.SUCCESS(response.hosts_loaded));
      setIsUploaded(true);
      
      // Fetch the uploaded data to pass to parent
      const dataResponse = await apiClient.getUploadedData();
      onUploadSuccess(dataResponse);
      
      // Don't clear anything - keep file visible until user clicks "New Upload"
    } catch (error) {
      const errorMessage = handleApiError(error, MESSAGES.UPLOAD.ERROR);
      setMessage(errorMessage);
      setIsUploaded(false);
    } finally {
      setIsLoading(false);
    }
  }, [file, onUploadSuccess]);

  return (
    <div>
      <div className="upload-container">
        <div className="file-input-container">
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            onChange={handleFileChange}
            className="file-input"
            disabled={isLoading}
          />
        </div>
        <div className="button-container">
          <button
            onClick={handleUpload}
            disabled={!file || isLoading}
            className={`upload-button ${isLoading ? 'loading' : ''}`}
          >
            {isLoading ? '⏳ Uploading...' : (file ? MESSAGES.UPLOAD.UPLOAD_BUTTON : MESSAGES.UPLOAD.NO_FILE)}
          </button>
        </div>
      </div>
      
      {/* File Information */}
      {file && (
        <div className={`file-info ${isUploaded ? 'uploaded' : ''}`}>
          <span>{isUploaded ? '✅' : '📄'}</span>
          <span className="file-name">
            {file.name}
          </span>
          <span className="file-size">
            ({(file.size / 1024).toFixed(1)} KB)
          </span>
          {isUploaded && (
            <span className="upload-status">
              Uploaded Successfully
            </span>
          )}
        </div>
      )}
      
      {message && (
        <div className={`alert ${isUploaded ? 'success' : 'error'}`}>
          {message}
        </div>
      )}
    </div>
  );
};

export default UploadDataset;
