import React, { useState } from "react";
import axios from "axios";

function Summarizer() {
  const [host, setHost] = useState("");
  const [summary, setSummary] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post("http://127.0.0.1:8000/summarize_host/", {
        ip: host,
      });
      setSummary(res.data.summary);
    } catch (err) {
      console.error(err);
      setSummary("Error fetching summary.");
    }
    setLoading(false);
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h2>Censys Host Summarizer</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="Enter host IP"
          style={{ padding: "8px", marginRight: "10px" }}
        />
        <button type="submit">Summarize</button>
      </form>

      {loading && <p>Loading...</p>}
      {summary && (
        <div style={{ marginTop: "20px" }}>
          <h3>Summary</h3>
          <p>{summary}</p>
        </div>
      )}
    </div>
  );
}

export default Summarizer;
