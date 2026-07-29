import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Activity, Cpu, Lock, CheckCircle2, XCircle, TrendingDown } from 'lucide-react';
import './index.css';

// Stunning Mock Data for the prototype
const MOCK_DATA = [
  { id: 6, time: '10:45:12 AM', agent: 'ag_Travel_Bot', action: 'Issue_Refund', amount: '$45.00', decision: 'ALLOW', hash: 'e3b0c442...' },
  { id: 5, time: '10:45:09 AM', agent: 'ag_Dispute_AI', action: 'Credit_Increase', amount: '$5,000.00', decision: 'DENY', hash: '8f434346...' },
  { id: 4, time: '10:44:55 AM', agent: 'ag_Travel_Bot', action: 'Issue_Refund', amount: '$120.00', decision: 'ALLOW', hash: 'a9f24e93...' },
  { id: 3, time: '10:44:30 AM', agent: 'ag_Fraud_Bot', action: 'Lock_Card', amount: 'N/A', decision: 'ALLOW', hash: 'c5d98412...' },
  { id: 2, time: '10:43:15 AM', agent: 'ag_Dispute_AI', action: 'Issue_Refund', amount: '$150.00', decision: 'ALLOW', hash: 'b1a2c3d4...' },
  { id: 1, time: '10:40:00 AM', agent: 'SYSTEM', action: 'INIT_GENESIS_BLOCK', amount: 'N/A', decision: 'ALLOW', hash: '00000000...' },
];

function App() {
  const [logs, setLogs] = useState([]);
  const [isFleetActive, setIsFleetActive] = useState(true);
  
  // Trust Economy State
  const [trustBudget, setTrustBudget] = useState(98.5); // Percentage
  const [activeAgents, setActiveAgents] = useState(14);

  // The Real-Time Polling Logic
  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/logs');
        if (!response.ok) throw new Error('API not ready');
        const data = await response.json();
        setLogs(data);
      } catch (error) {
        setLogs(MOCK_DATA);
      }
    };

    const fetchTrustEconomy = async () => {
      if (!isFleetActive) return;
      try {
        const response = await fetch('http://localhost:8000/api/trust-economy');
        if (response.ok) {
          const data = await response.json();
          setTrustBudget(data.fleet_budget);
          if (data.active_agents > 0) {
            setActiveAgents(data.active_agents);
          }
        }
      } catch (error) {
        console.error("Trust economy fetch failed", error);
      }
    };

    // Initial fetch
    fetchLogs();
    fetchTrustEconomy();
    
    const interval = setInterval(() => {
      fetchLogs();
      fetchTrustEconomy();
    }, 2000);
    
    return () => clearInterval(interval);
  }, [isFleetActive]);

  const handleKillSwitch = () => {
    setIsFleetActive(false);
    setTrustBudget(0);
    setActiveAgents(0);
    alert("CRITICAL ALERT: Sentinel Fleet Kill Switch Activated. All AI Agents Frozen.");
  };

  return (
    <div className="dashboard-container">
      
      {/* Header */}
      <header className="header">
        <div className="header-title">
          <Shield size={36} color={isFleetActive ? "#3B82F6" : "#EF4444"} style={{ filter: `drop-shadow(0 0 10px ${isFleetActive ? 'rgba(59, 130, 246, 0.5)' : 'rgba(239, 68, 68, 0.5)'})`}} />
          <h1>SENTINEL COMMAND</h1>
        </div>
        
        <div className={`status-badge ${isFleetActive ? 'active' : 'frozen'}`}>
          <div className="status-dot"></div>
          {isFleetActive ? "FLEET ACTIVE" : "FLEET FROZEN"}
        </div>
      </header>

      {/* Main Grid */}
      <main className="main-content">
        
        {/* Sidebar Controls */}
        <aside className="sidebar">
          
          {/* Trust Economy Card (NEW) */}
          <div className="card">
            <h2><TrendingDown size={18} /> Trust Economy</h2>
            <div className="trust-metrics">
              
              <div>
                <div className="metric-row">
                  <span className="metric-label">Shared Fleet Budget</span>
                  <span className="metric-value" style={{ color: trustBudget > 70 ? 'var(--accent-green)' : trustBudget > 40 ? '#F59E0B' : 'var(--accent-red)' }}>
                    {trustBudget.toFixed(1)}%
                  </span>
                </div>
                <div className="progress-bar-container">
                  <div 
                    className="progress-bar" 
                    style={{ 
                      width: `${trustBudget}%`,
                      backgroundColor: trustBudget > 70 ? 'var(--accent-green)' : trustBudget > 40 ? '#F59E0B' : 'var(--accent-red)'
                    }}
                  ></div>
                </div>
                <p style={{ color: "var(--text-secondary)", fontSize: "0.75rem", marginTop: "0.5rem" }}>
                  Contagion risk updates in real-time.
                </p>
              </div>

              <div className="metric-row" style={{ marginTop: "1rem" }}>
                <span className="metric-label" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}><Cpu size={16} /> Active Agents</span>
                <span className="metric-value" style={{ fontSize: "1.5rem" }}>{activeAgents}</span>
              </div>
              
              <div className="metric-row">
                <span className="metric-label" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}><Activity size={16} /> Edge Latency</span>
                <span className="metric-value" style={{ fontSize: "1.5rem" }}>0.8 ms</span>
              </div>

            </div>
          </div>

          <div className="card" style={{ display: "flex", flexDirection: "column", alignItems: "center", border: isFleetActive ? "1px solid var(--border-color)" : "1px solid rgba(239, 68, 68, 0.4)" }}>
            <h2><Lock size={18} /> Master Override</h2>
            <div className="kill-switch-container">
              <button className="kill-switch" onClick={handleKillSwitch}>
                EMERGENCY STOP
              </button>
              <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", textAlign: "center", marginTop: "1rem", lineHeight: "1.5" }}>
                Instantly revokes Visa credentials for all agents across the network.
              </p>
            </div>
          </div>
        </aside>

        {/* Audit Log Table */}
        <div className="card" style={{ display: "flex", flexDirection: "column", padding: 0, overflow: "hidden" }}>
          <h2 style={{ padding: "1.75rem 1.75rem 0 1.75rem" }}><ShieldAlert size={18} /> Immutable Audit Ledger (KYA Passport)</h2>
          <div className="log-table-wrapper" style={{ padding: "0 1.75rem 1.75rem 1.75rem" }}>
            <table className="log-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Agent ID</th>
                  <th>Action</th>
                  <th>Amount</th>
                  <th>Governance Decision</th>
                  <th>SHA-256 Chain</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ color: "var(--text-secondary)" }}>{log.time}</td>
                    <td>
                      <div className="agent-name">
                        <Cpu size={14} color="var(--text-secondary)" />
                        {log.agent}
                      </div>
                    </td>
                    <td>{log.action}</td>
                    <td style={{ fontFamily: "monospace", color: "var(--text-primary)" }}>{log.amount}</td>
                    <td>
                      <span className={log.decision === 'ALLOW' ? 'tag-allow' : 'tag-deny'}>
                        {log.decision === 'ALLOW' ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                        {log.decision}
                      </span>
                    </td>
                    <td>
                      <span className="hash-cell">
                        {log.hash}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </main>
    </div>
  );
}

export default App;
