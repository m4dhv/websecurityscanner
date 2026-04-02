import React, { useState, useEffect } from 'react';
import { Lock, Database, Clock, Globe } from 'lucide-react';

export default function Admin({ theme }) {
  const [jwt, setJwt] = useState(sessionStorage.getItem('websec_admin_jwt') || '');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [scans, setScans] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const surfaceClass = theme === 'dark' ? 'bg-[#0d111c] border-[#1e2540]' : 'bg-white border-gray-200';

  useEffect(() => {
    if (jwt) fetchScans();
  }, [jwt]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch('http://localhost:8000/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      if (!res.ok) throw new Error("Invalid credentials");
      const data = await res.json();
      setJwt(data.access_token);
      sessionStorage.setItem('websec_admin_jwt', data.access_token);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const fetchScans = async () => {
    try {
      const res = await fetch('http://localhost:8000/scans', {
        headers: { 'Authorization': `Bearer ${jwt}` }
      });
      if (res.status === 401) {
        setJwt('');
        sessionStorage.removeItem('websec_admin_jwt');
        return;
      }
      const data = await res.json();
      setScans(data);
    } catch (err) {
      console.error("Failed to fetch logs", err);
    }
  };

  if (!jwt) {
    return (
      <div className={`max-w-md mx-auto p-8 rounded-2xl border ${surfaceClass} shadow-2xl mt-20`}>
        <div className="flex justify-center mb-6">
          <div className="p-4 bg-red-500/10 rounded-full">
            <Lock className="w-8 h-8 text-red-500" />
          </div>
        </div>
        <h2 className="text-2xl font-bold mb-6 text-center">Admin Gateway</h2>
        {error && <p className="text-red-500 text-sm mb-4 text-center font-mono bg-red-500/10 p-2 rounded">{error}</p>}
        <form onSubmit={handleLogin} className="flex flex-col gap-4">
          <input 
            type="text" placeholder="Admin Username" 
            className={`w-full p-4 rounded-xl border font-mono outline-none ${theme === 'dark' ? 'bg-[#151926] border-gray-800' : 'bg-gray-50 border-gray-300'}`}
            value={username} onChange={(e) => setUsername(e.target.value)}
          />
          <input 
            type="password" placeholder="Password" 
            className={`w-full p-4 rounded-xl border font-mono outline-none ${theme === 'dark' ? 'bg-[#151926] border-gray-800' : 'bg-gray-50 border-gray-300'}`}
            value={password} onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit" disabled={loading} className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-4 rounded-xl uppercase tracking-wider mt-2 transition-colors">
            {loading ? 'Authenticating...' : 'Access Console'}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-3xl font-bold flex items-center gap-3">
            <Database className="text-blue-500" /> Global Scan Telemetry
          </h2>
          <p className="text-gray-500 mt-2 font-mono text-sm">Real-time aggregate logs (PII scrubbed)</p>
        </div>
        <button 
          onClick={() => { setJwt(''); sessionStorage.removeItem('websec_admin_jwt'); }}
          className="text-sm font-bold text-red-500 hover:text-red-400 uppercase tracking-wider"
        >
          Terminate Session
        </button>
      </div>

      <div className={`rounded-xl border ${surfaceClass} overflow-hidden shadow-xl`}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className={`text-xs uppercase font-mono tracking-widest ${theme === 'dark' ? 'bg-[#151926] text-gray-400' : 'bg-gray-100 text-gray-600'}`}>
              <tr>
                <th className="px-6 py-4">ID</th>
                <th className="px-6 py-4 flex items-center gap-2"><Globe className="w-4 h-4"/> Client IP</th>
                <th className="px-6 py-4">Target Domain</th>
                <th className="px-6 py-4 flex items-center gap-2"><Clock className="w-4 h-4"/> Timestamp</th>
                <th className="px-6 py-4">Issues Found</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans.length === 0 ? (
                <tr><td colSpan="5" className="px-6 py-8 text-center text-gray-500">No telemetry data available.</td></tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.id} className={`${theme === 'dark' ? 'hover:bg-[#151926]' : 'hover:bg-gray-50'} transition-colors`}>
                    <td className="px-6 py-4 font-mono text-gray-500">#{scan.id}</td>
                    <td className="px-6 py-4 font-mono">{scan.client_ip}</td>
                    <td className="px-6 py-4 font-bold text-green-500">{scan.target}</td>
                    <td className="px-6 py-4 font-mono text-gray-500">{new Date(scan.timestamp).toLocaleString()}</td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        {scan.metrics.sqli_count > 0 && <span className="px-2 py-1 rounded bg-red-500/20 text-red-500 font-bold text-xs">SQLi: {scan.metrics.sqli_count}</span>}
                        {scan.metrics.xss_count > 0 && <span className="px-2 py-1 rounded bg-orange-500/20 text-orange-500 font-bold text-xs">XSS: {scan.metrics.xss_count}</span>}
                        {scan.metrics.total_vulns === 0 && <span className="px-2 py-1 rounded bg-green-500/20 text-green-500 font-bold text-xs">CLEAN</span>}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}