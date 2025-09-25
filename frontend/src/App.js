import React, { useState } from "react";
import Summarizer from "./Summarizer";
import UploadDataset from "./UploadDataset";

function App() {
  const [datasetUploaded, setDatasetUploaded] = useState(false);

  return (
    <div className="App">
      <h1>Censys Host Summarizer</h1>
      {!datasetUploaded ? (
        <UploadDataset onUploadSuccess={() => setDatasetUploaded(true)} />
      ) : (
        <Summarizer />
      )}
    </div>
  );
}

export default App;
