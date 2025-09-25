import React, { useState } from "react";
import axios from "axios";

const UploadDataset = ({ onUploadSuccess }) => {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage("Please select a JSON file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await axios.post(
        "http://127.0.0.1:8000/upload_dataset/",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      setMessage(`Dataset uploaded: ${response.data.hosts_loaded} hosts loaded`);
      onUploadSuccess();
    } catch (error) {
      setMessage("Error uploading dataset");
      console.error(error);
    }
  };

  return (
    <div>
      <h3>Upload JSON Dataset</h3>
      <input type="file" accept=".json" onChange={handleFileChange} />
      <button onClick={handleUpload}>Upload</button>
      <p>{message}</p>
    </div>
  );
};

export default UploadDataset;
