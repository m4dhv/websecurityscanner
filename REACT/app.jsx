import React, { useState } from 'react';
import Scanner from './Scanner';
import Admin from './Admin';
import { Shield, Settings, Home, Sun, Moon } from 'lucide-react';

export default function App() {
  const [view, setView] = useState('scanner'); // 'scanner' or 'admin'
  const [theme, setTheme] = useState('dark');
  const [apiKey, setApiKey] = useState(localStorage.getItem('websec_api_key') || '');

  const toggleTheme = () => setTheme(theme === 'dark' ? 'light' : 'dark');

  // Theme configuration (Matches Streamlit CSS)
  const themeClasses = theme === 'dark' 
    ? 'bg-[#07090f] text-[#e8ecf4] border-[#1e2540]' 
    : 'bg-[#f8faff] text-[#0f172a] border-[#e2e8f5]';

  return (
    <div className={`min-h-screen transition-colors duration-300 font-sans ${themeClasses}`}>
      <div className="max-w-5xl mx-auto px-6 py-8">
        
        {/* Top Navigation */}
        <nav className="flex justify-between items-center mb-12">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-600 rounded-lg flex items-center justify-center shadow-[0_4px_15px_rgba(34,197,94,0.2)]">
              <Shield className="text-white w-6 h-6" />
            </div>
            <div className="font-extrabold text-2xl tracking-tight">
              Web<span className="text-green-600">Sec</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button 
              onClick={toggleTheme}
              className="p-2 rounded-full border border-gray-600 hover:border-green-500 transition-all"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <button
              onClick={() => setView(view === 'scanner' ? 'admin' : 'scanner')}
              className={`flex items-center gap-2 px-4 py-2 rounded-full font-bold text-sm tracking-wide transition-all ${
                theme === 'dark' ? 'bg-[#151926] hover:bg-[#1e2540]' : 'bg-gray-200 hover:bg-gray-300'
              }`}
            >
              {view === 'scanner' ? <><Settings className="w-4 h-4"/> Admin Panel</> : <><Home className="w-4 h-4"/> Scanner</>}
            </button>
          </div>
        </nav>

        {/* View Routing */}
        {view === 'scanner' ? (
          <Scanner apiKey={apiKey} setApiKey={setApiKey} theme={theme} />
        ) : (
          <Admin theme={theme} />
        )}

        {/* Footer */}
        <div className="mt-16 pt-8 border-t border-gray-800 text-center text-gray-500 font-mono text-xs">
          ⚠️ AUTHORIZED USE ONLY &nbsp; • &nbsp; COMPLIANCE REQUIRED &nbsp; • &nbsp; WEBSEC ENGINE V2.5
        </div>
      </div>
    </div>
  );
}