import React, { useState, useEffect } from 'react';
import { apiClient, handleApiError } from '../utils';
import { Alert } from './UI';

const StatusPanel = ({ className, style }) => {
  const [healthStatus, setHealthStatus] = useState(null);
  const [apiKeys, setApiKeys] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        setLoading(true);
        setError(null);

        const [health, keys, statsData] = await Promise.allSettled([
          apiClient.healthCheck(),
          apiClient.checkApiKeys(),
          apiClient.getStats().catch(() => null) // Stats might not be available if no dataset
        ]);

        setHealthStatus(health.status === 'fulfilled' ? health.value : null);
        setApiKeys(keys.status === 'fulfilled' ? keys.value : null);
        setStats(statsData.status === 'fulfilled' ? statsData.value : null);

        if (health.status === 'rejected') {
          setError('Unable to connect to backend server');
        }
      } catch (err) {
        setError(handleApiError(err, 'Failed to fetch status'));
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    // Refresh every 30 seconds
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className={className} style={style}>
        <div style={{ 
          padding: '16px', 
          textAlign: 'center', 
          color: '#64748b',
          fontSize: '14px'
        }}>
          ⏳ Loading status...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={className} style={style}>
        <Alert type="error">
          {error}
        </Alert>
      </div>
    );
  }

  return (
    <div className={className} style={style}>
      {/* Health Status */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          marginBottom: '8px'
        }}>
          <div style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: healthStatus ? '#10b981' : '#ef4444'
          }}></div>
          <span style={{ 
            fontSize: '14px', 
            fontWeight: '600',
            color: '#374151'
          }}>
            Backend Status
          </span>
        </div>
        {healthStatus && (
          <div style={{ 
            fontSize: '12px', 
            color: '#64748b',
            marginLeft: '16px'
          }}>
            {healthStatus.hosts_loaded} hosts loaded
            {healthStatus.last_upload && (
              <span> • Last upload: {new Date(healthStatus.last_upload).toLocaleString()}</span>
            )}
          </div>
        )}
      </div>

      {/* API Keys Status */}
      {apiKeys && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            marginBottom: '8px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: apiKeys.has_any_key ? '#10b981' : '#f59e0b'
            }}></div>
            <span style={{ 
              fontSize: '14px', 
              fontWeight: '600',
              color: '#374151'
            }}>
              AI Services
            </span>
          </div>
          <div style={{ 
            fontSize: '12px', 
            color: '#64748b',
            marginLeft: '16px'
          }}>
            {apiKeys.has_any_key ? (
              <>
                {apiKeys.GEMINI_API_KEY && 'Gemini • '}
                {apiKeys.OPENAI_API_KEY && 'OpenAI • '}
                AI summaries available
              </>
            ) : (
              'No AI keys configured - using fallback summaries'
            )}
          </div>
        </div>
      )}

      {/* Dataset Statistics */}
      {stats && (
        <div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            marginBottom: '8px'
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: '#3b82f6'
            }}></div>
            <span style={{ 
              fontSize: '14px', 
              fontWeight: '600',
              color: '#374151'
            }}>
              Dataset Stats
            </span>
          </div>
          <div style={{ 
            fontSize: '12px', 
            color: '#64748b',
            marginLeft: '16px',
            lineHeight: '1.4'
          }}>
            <div>Total hosts: {stats.total_hosts}</div>
            <div>Avg services: {stats.avg_services_per_host.toFixed(1)}</div>
            <div>Avg vulnerabilities: {stats.avg_vulnerabilities_per_host.toFixed(1)}</div>
            {stats.risk_distribution && (
              <div style={{ marginTop: '4px' }}>
                Risk levels: {Object.entries(stats.risk_distribution)
                  .map(([level, count]) => `${level}: ${count}`)
                  .join(', ')}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default StatusPanel;

