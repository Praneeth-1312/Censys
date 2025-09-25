import React, { useState, useRef, useEffect, useCallback } from "react";
import { apiClient, handleApiError, validateFile } from "./utils";
import { MESSAGES, UI_CONSTANTS } from "./constants";
import { Button, Input, Alert } from "./components/UI";

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

  const containerStyles = {
    display: "flex",
    alignItems: "center",
    gap: UI_CONSTANTS.SPACING.XL,
    marginBottom: UI_CONSTANTS.SPACING.LG,
    flexWrap: "wrap"
  };

  const fileInputContainerStyles = {
    flex: "1",
    minWidth: "280px",
    maxWidth: "400px"
  };

  const buttonContainerStyles = {
    flexShrink: "0"
  };

  const fileInfoStyles = {
    marginTop: UI_CONSTANTS.SPACING.SM,
    padding: UI_CONSTANTS.SPACING.SM + ' ' + UI_CONSTANTS.SPACING.MD,
    backgroundColor: isUploaded ? UI_CONSTANTS.COLORS.GRAY[50] : UI_CONSTANTS.COLORS.GRAY[100],
    border: `1px solid ${isUploaded ? UI_CONSTANTS.COLORS.SUCCESS : UI_CONSTANTS.COLORS.GRAY[300]}`,
    borderRadius: UI_CONSTANTS.BORDER_RADIUS.SM,
    fontSize: '13px',
    color: UI_CONSTANTS.COLORS.GRAY[700],
    display: 'flex',
    alignItems: 'center',
    gap: UI_CONSTANTS.SPACING.SM
  };

  return (
    <div>
      <div style={containerStyles}>
        <div style={fileInputContainerStyles}>
          <Input
            ref={fileInputRef}
            type="file"
            accept=".json"
            onChange={handleFileChange}
            disabled={isLoading}
          />
        </div>
        <div style={buttonContainerStyles}>
          <Button
            onClick={handleUpload}
            disabled={!file || isLoading}
            loading={isLoading}
            variant="primary"
            size="md"
          >
            {file ? MESSAGES.UPLOAD.UPLOAD_BUTTON : MESSAGES.UPLOAD.NO_FILE}
          </Button>
        </div>
      </div>
      
      {/* File Information */}
      {file && (
        <div style={fileInfoStyles}>
          <span>{isUploaded ? '✅' : '📄'}</span>
          <span style={{ fontWeight: '500' }}>
            {file.name}
          </span>
          <span style={{ color: UI_CONSTANTS.COLORS.GRAY[500] }}>
            ({(file.size / 1024).toFixed(1)} KB)
          </span>
          {isUploaded && (
            <span style={{ 
              color: UI_CONSTANTS.COLORS.SUCCESS, 
              fontWeight: '600',
              marginLeft: 'auto'
            }}>
              Uploaded Successfully
            </span>
          )}
        </div>
      )}
      
      {message && (
        <Alert type={isUploaded ? "success" : "error"}>
          {message}
        </Alert>
      )}
    </div>
  );
};

export default UploadDataset;
