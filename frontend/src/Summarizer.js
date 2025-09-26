import React, { useState } from "react";
import axios from "axios";
import { handleApiError } from "./utils";

function Summarizer({ hasDataset = false }) {
  const [host, setHost] = useState("");
  const [summary, setSummary] = useState("");
  const [allSummaries, setAllSummaries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [batchLoading, setBatchLoading] = useState(false);
  // Reset all state when component mounts (when new dataset is uploaded)
  React.useEffect(() => {
    setHost("");
    setSummary("");
    setAllSummaries([]);
    setLoading(false);
    setBatchLoading(false);
  }, []);

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
      setSummary(handleApiError(err, "Error fetching summary."));
    }
    setLoading(false);
  };

  const handleSummarizeAll = async () => {
    setBatchLoading(true);
    setAllSummaries([]);
    try {
      const res = await axios.get("http://127.0.0.1:8000/summarize_all/");
      setAllSummaries(res.data.summaries);
    } catch (err) {
      console.error(err);
      setAllSummaries([{ ip: "Error", summary: handleApiError(err, "Error fetching summaries for all hosts.") }]);
    }
    setBatchLoading(false);
  };


  return (
    <div style={{ padding: "0", fontFamily: "inherit" }}>
      {/* Reset Message */}
      
      {/* Individual Host Summary */}
      <div style={{ 
        marginBottom: "32px", 
        background: "white",
        border: "1px solid #e2e8f0", 
        borderRadius: "12px", 
        padding: "24px",
        boxShadow: "0 1px 3px rgba(0,0,0,0.1)"
      }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          marginBottom: "20px"
        }}>
          <div style={{
            width: "40px",
            height: "40px",
            background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
            borderRadius: "10px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "18px"
          }}>
            🔍
          </div>
          <div>
            <h3 style={{
              margin: "0",
              fontSize: "1.25rem",
              fontWeight: "600",
              color: "#1e293b"
            }}>
              Summarize Individual Host
            </h3>
            <p style={{
              margin: "4px 0 0 0",
              fontSize: "0.875rem",
              color: "#64748b"
            }}>
              Enter a specific IP address to get detailed analysis
            </p>
          </div>
        </div>
        
        <form onSubmit={handleSubmit} style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="Enter host IP address"
              style={{ 
                flex: "1",
                minWidth: "250px",
                padding: "12px 16px",
                border: "2px solid #e2e8f0",
                borderRadius: "8px",
                fontSize: "14px",
                backgroundColor: "white",
                transition: "all 0.2s ease"
              }}
              onFocus={(e) => {
                e.target.style.borderColor = "#3b82f6";
                e.target.style.boxShadow = "0 0 0 3px rgba(59, 130, 246, 0.1)";
              }}
              onBlur={(e) => {
                e.target.style.borderColor = "#e2e8f0";
                e.target.style.boxShadow = "none";
              }}
            />
            <button 
              type="submit" 
              disabled={loading || !host.trim()}
              style={{
                padding: "12px 24px",
                background: loading || !host.trim() ? "#94a3b8" : "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
                color: "white",
                border: "none",
                borderRadius: "8px",
                fontSize: "14px",
                fontWeight: "600",
                cursor: loading || !host.trim() ? "not-allowed" : "pointer",
                transition: "all 0.2s ease",
                boxShadow: loading || !host.trim() ? "none" : "0 4px 12px rgba(59, 130, 246, 0.3)",
                minWidth: "140px"
              }}
              onMouseOver={(e) => {
                if (!loading && host.trim()) {
                  e.target.style.transform = "translateY(-1px)";
                  e.target.style.boxShadow = "0 6px 16px rgba(59, 130, 246, 0.4)";
                }
              }}
              onMouseOut={(e) => {
                if (!loading && host.trim()) {
                  e.target.style.transform = "translateY(0)";
                  e.target.style.boxShadow = "0 4px 12px rgba(59, 130, 246, 0.3)";
                }
              }}
            >
              {loading ? "⏳ Analyzing..." : "🚀 Summarize"}
            </button>
          </div>
        </form>

        {summary && (
          <div style={{ 
            marginTop: "20px",
            padding: "20px",
            background: "linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%)",
            borderRadius: "8px",
            border: "1px solid #e2e8f0"
          }}>
            <h4 style={{
              margin: "0 0 12px 0",
              fontSize: "1rem",
              fontWeight: "600",
              color: "#374151",
              display: "flex",
              alignItems: "center",
              gap: "8px"
            }}>
              📋 Analysis Summary
            </h4>
            <p style={{ 
              margin: "0",
              lineHeight: "1.6",
              color: "#4b5563",
              fontSize: "14px"
            }}>
              {summary}
            </p>
          </div>
        )}
      </div>

      {/* Batch Summary */}
      <div style={{ 
        background: "white",
        border: "1px solid #e2e8f0", 
        borderRadius: "12px", 
        padding: "24px",
        boxShadow: "0 1px 3px rgba(0,0,0,0.1)"
      }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          marginBottom: "20px"
        }}>
          <div style={{
            width: "40px",
            height: "40px",
            background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
            borderRadius: "10px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "18px"
          }}>
            📊
          </div>
          <div>
            <h3 style={{
              margin: "0",
              fontSize: "1.25rem",
              fontWeight: "600",
              color: "#1e293b"
            }}>
              Summarize All Hosts
            </h3>
            <p style={{
              margin: "4px 0 0 0",
              fontSize: "0.875rem",
              color: "#64748b"
            }}>
              Generate comprehensive summaries for all hosts in the dataset
            </p>
          </div>
        </div>
        
        <button 
          onClick={handleSummarizeAll} 
          disabled={batchLoading}
          style={{ 
            padding: "14px 28px", 
            background: batchLoading ? "#94a3b8" : "linear-gradient(135deg, #10b981 0%, #059669 100%)", 
            color: "white", 
            border: "none", 
            borderRadius: "8px",
            cursor: batchLoading ? "not-allowed" : "pointer",
            fontSize: "14px",
            fontWeight: "600",
            transition: "all 0.2s ease",
            boxShadow: batchLoading ? "none" : "0 4px 12px rgba(16, 185, 129, 0.3)",
            marginBottom: "24px"
          }}
          onMouseOver={(e) => {
            if (!batchLoading) {
              e.target.style.transform = "translateY(-1px)";
              e.target.style.boxShadow = "0 6px 16px rgba(16, 185, 129, 0.4)";
            }
          }}
          onMouseOut={(e) => {
            if (!batchLoading) {
              e.target.style.transform = "translateY(0)";
              e.target.style.boxShadow = "0 4px 12px rgba(16, 185, 129, 0.3)";
            }
          }}
        >
          {batchLoading ? "⏳ Processing All Hosts..." : "🚀 Summarize All Hosts"}
        </button>

        {allSummaries.length > 0 && (
          <div>
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "16px"
            }}>
              <h4 style={{
                margin: "0",
                fontSize: "1rem",
                fontWeight: "600",
                color: "#374151"
              }}>
                📈 Batch Analysis Results
              </h4>
              <span style={{
                background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
                color: "white",
                padding: "4px 8px",
                borderRadius: "12px",
                fontSize: "12px",
                fontWeight: "600"
              }}>
                {allSummaries.length} hosts
              </span>
            </div>
            <div style={{ 
              maxHeight: "500px", 
              overflowY: "auto",
              border: "1px solid #e2e8f0",
              borderRadius: "8px",
              backgroundColor: "#f8fafc"
            }}>
              {allSummaries.map((item, index) => (
                <div key={index} style={{ 
                  padding: "16px", 
                  borderBottom: index < allSummaries.length - 1 ? "1px solid #e2e8f0" : "none",
                  backgroundColor: "white",
                  transition: "all 0.2s ease"
                }}>
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    marginBottom: "8px"
                  }}>
                    <div style={{
                      width: "8px",
                      height: "8px",
                      background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
                      borderRadius: "50%"
                    }}></div>
                    <strong style={{ 
                      color: "#1e40af",
                      fontSize: "14px",
                      fontWeight: "600"
                    }}>
                      Host: {item.ip}
                    </strong>
                  </div>
                  <p style={{ 
                    margin: "0",
                    lineHeight: "1.5",
                    color: "#4b5563",
                    fontSize: "13px"
                  }}>
                    {item.summary}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Summarizer;
