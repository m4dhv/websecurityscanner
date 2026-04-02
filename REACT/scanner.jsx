import React, { useState, useEffect } from 'react';
import { Activity, Search, AlertTriangle, ShieldCheck, Key } from 'lucide-react';

export default function Scanner({ apiKey, setApiKey, theme }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [status, setStatus] = useState('IDLE'); // IDLE, SCANNING, COMPLETE, ERROR
  const [results, setResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [tempKey, setTempKey] = useState('');

  const surfaceClass = theme === 'dark' ? 'bg-[#0d111c] border-[#1e2540]' : 'bg-white border-gray-200';

  const handleSaveKey = (e) => {
    e.preventDefault();
    if (tempKey.trim().length > 5) {
      setApiKey(tempKey.trim());
      localStorage.setItem('websec_api_key', tempKey.trim());
    }
  };

  const startScan = async (type) => {
    if (!targetUrl) return setErrorMsg("Target URL cannot be empty.");
    if (!/^https?:\/\//i.test(targetUrl)) return setErrorMsg("URL must start with http:// or https://");

    setStatus('SCANNING');
    setErrorMsg('');
    setResults(null);

    try {
      const res = await fetch('http://localhost:8000/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey
        },
        body: JSON.stringify({ target_url: targetUrl, scan_type: type })
      });

      if (!res.ok) throw new Error(await res.text());
      
      const data = await res.json();
      setResults(data);
      setStatus('COMPLETE');
    } catch (err) {
      setStatus('ERROR');
      setErrorMsg(err.message.includes("401") ? "Invalid API Key. Please update your key." : "Scan failed: Network or server error.");
    }
  };

  // --- API Key Gate ---
  if (!apiKey) {
    return (
      <div className={`max-w-md mx-auto p-8 rounded-2xl border ${surfaceClass} shadow-2xl text-center mt-20`}>
        <Key className="w-12 h-12 mx-auto text-green-500 mb-4" />
        <h2 className="text-2xl font-bold mb-2">API Authentication</h2>
        <p className="text-gray-500 mb-6 text-sm">Enter your provided API key to access the scanner engine.</p>
        <form onSubmit={handleSaveKey} className="flex flex-col gap-4">
          <input 
            type="text" 
            placeholder="sk_..." 
            className={`w-full p-4 rounded-xl border font-mono outline-none focus:border-green-500 transition-colors ${theme === 'dark' ? 'bg-[#151926] border-gray-800' : 'bg-gray-50 border-gray-300'}`}
            value={tempKey}
            onChange={(e) => setTempKey(e.target.value)}
          />
          <button type="submit" className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-4 rounded-xl uppercase tracking-wider transition-colors">
            Unlock Scanner
          </button>
        </form>
      </div>
    );
  }

  // --- Main Scanner UI ---
  return (
    <div className="animate-fade-in">
      <div className="mb-8">
        <p className="text-green-500 font-mono text-xs font-bold tracking-widest mb-1">AUTOMATED SECURITY AUDIT</p>
        <h1 className="text-4xl font-extrabold">Website Security Scanner</h1>
      </div>

      {/* Input Area */}
      <div className="flex flex-col md:flex-row gap-4 mb-10">
        <input 
          type="text" 
          placeholder="https://target-website.com" 
          className={`flex-1 p-4 rounded-xl border font-mono outline-none focus:border-green-500 transition-colors ${surfaceClass}`}
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          disabled={status === 'SCANNING'}
        />
        <button onClick={() => startScan('quick')} disabled={status === 'SCANNING'} className="bg-green-600 hover:bg-green-700 text-white font-bold px-8 py-4 rounded-xl uppercase tracking-wider disabled:opacity-50 flex items-center justify-center gap-2">
          {status === 'SCANNING' ? <Activity className="animate-pulse" /> : '⚡ Quick'}
        </button>
        <button onClick={() => startScan('deep')} disabled={status === 'SCANNING'} className={`border font-bold px-8 py-4 rounded-xl uppercase tracking-wider disabled:opacity-50 flex items-center justify-center gap-2 ${theme === 'dark' ? 'border-gray-700 hover:bg-gray-800' : 'border-gray-300 hover:bg-gray-100'}`}>
          <Search className="w-5 h-5" /> Deep
        </button>
      </div>

      {errorMsg && <div className="bg-red-500/10 border border-red-500 text-red-500 p-4 rounded-xl mb-8 font-mono text-sm">{errorMsg}</div>}

      {/* Scanning Animation */}
      {status === 'SCANNING' && (
        <div className={`p-12 rounded-2xl border ${surfaceClass} text-center flex flex-col items-center justify-center mb-8`}>
          <div className="w-16 h-16 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin mb-6"></div>
          <h3 className="text-xl font-bold animate-pulse">Analyzing target architecture...</h3>
          <p className="text-gray-500 font-mono mt-2">Crawling endpoints and injecting payloads</p>
        </div>
      )}

      {/* Results Dashboard */}
      {results && (
        <div>
          {/* Metrics Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <MetricCard title="Endpoints" value={results.metrics.endpoints_scanned} theme={theme} />
            <MetricCard title="Critical (SQLi)" value={results.metrics.sqli_count} color="text-red-500" theme={theme} />
            <MetricCard title="High (XSS)" value={results.metrics.xss_count} color="text-orange-500" theme={theme} />
            <MetricCard title="Med (Info)" value={results.metrics.info_count} color="text-yellow-500" theme={theme} />
          </div>

          <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
            <AlertTriangle className="text-orange-500" /> Security Findings
          </h3>
          
          {results.vulnerabilities.length === 0 ? (
            <div className={`p-8 rounded-xl border ${surfaceClass} flex items-center gap-4 text-green-500`}>
              <ShieldCheck className="w-8 h-8" />
              <div>
                <p className="font-bold text-lg">Target surface appears clean.</p>
                <p className="text-sm opacity-80">No vulnerabilities detected within the defined scope.</p>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {results.vulnerabilities.map((vuln, idx) => (
                <div key={idx} className={`p-4 rounded-xl border ${surfaceClass} overflow-hidden`}>
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`px-2 py-1 rounded text-xs font-bold font-mono ${vuln.type.includes('SQL') ? 'bg-red-500/20 text-red-500' : vuln.type.includes('XSS') ? 'bg-orange-500/20 text-orange-500' : 'bg-yellow-500/20 text-yellow-500'}`}>
                      {vuln.type.includes('SQL') ? 'CRITICAL' : vuln.type.includes('XSS') ? 'HIGH' : 'MEDIUM'}
                    </span>
                    <span className="font-bold text-sm">{vuln.type}</span>
                  </div>
                  <div className="grid grid-cols-[100px_1fr] gap-2 text-sm font-mono mt-4">
                    <div className="text-gray-500">URL</div>
                    <div className="break-all">{vuln.url}</div>
                    {vuln.parameter && <><div className="text-gray-500">PARAM</div><div>{vuln.parameter}</div></>}
                    {vuln.payload && <><div className="text-gray-500">PAYLOAD</div><div className="text-orange-400 break-all">{vuln.payload}</div></>}
                    {vuln.info_type && <><div className="text-gray-500">TYPE</div><div>{vuln.info_type}</div></>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MetricCard({ title, value, color = "", theme }) {
  const surfaceClass = theme === 'dark' ? 'bg-[#0d111c] border-[#1e2540] hover:border-green-500' : 'bg-white border-gray-200 hover:border-green-500';
  return (
    <div className={`p-6 rounded-2xl border transition-all transform hover:-translate-y-1 ${surfaceClass}`}>
      <div className="text-gray-500 text-xs font-mono uppercase tracking-widest mb-2">{title}</div>
      <div className={`text-4xl font-extrabold ${color}`}>{value}</div>
    </div>
  );
}