"use client";

import { useState } from 'react';
import { Search, Globe, Server, ShieldCheck, FileKey, Activity, AlertTriangle } from 'lucide-react';
import useSWR from 'swr';

// Fungsi Fetcher untuk SWR
const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Home() {
  const [searchInput, setSearchInput] = useState('');
  const [target, setTarget] = useState('');

  // SWR akan otomatis mengelola state loading dan error
  const { data, error, isLoading } = useSWR(
    target ? `/api/lookup?target=${target}` : null,
    fetcher
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      setTarget(searchInput.trim());
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans selection:bg-blue-200">
      {/* Header / Navbar */}
      <header className="bg-white border-b border-slate-200 py-4 px-6 md:px-12 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-6 h-6 text-blue-600" />
          <h1 className="text-xl font-bold tracking-tight">RifqyLookup</h1>
        </div>
        <nav className="text-sm font-medium text-slate-500">
          OSINT & Reconnaissance Tool
        </nav>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        {/* Search Section */}
        <div className="flex flex-col items-center mb-16">
          <h2 className="text-3xl md:text-4xl font-extrabold mb-4 text-center">
            Investigasi Domain & IP
          </h2>
          <p className="text-slate-500 mb-8 text-center max-w-2xl">
            Masukkan nama domain atau alamat IP untuk menganalisis infrastruktur jaringan, keamanan web, dan rekam jejak digital.
          </p>
          
          <form onSubmit={handleSearch} className="w-full max-w-2xl relative">
            <div className="relative flex items-center">
              <Search className="absolute left-4 w-5 h-5 text-slate-400" />
              <input
                type="text"
                placeholder="Contoh: google.com atau 8.8.8.8"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="w-full pl-12 pr-32 py-4 rounded-xl border border-slate-300 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all bg-white"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="absolute right-2 px-6 py-2 bg-slate-900 hover:bg-slate-800 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {isLoading ? 'Mencari...' : 'Analisis'}
              </button>
            </div>
          </form>
        </div>

        {/* Error State */}
        {error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5" />
            <p>Terjadi kesalahan saat mengambil data. Pastikan target valid.</p>
          </div>
        )}
        
        {data?.error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5" />
            <p>{data.error}</p>
          </div>
        )}

        {/* Results Dashboard */}
        {data && !data.error && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            
            {/* Network Recon Card */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <Globe className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-semibold">Network & DNS Recon</h3>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-slate-500 mb-1">Target</p>
                  <p className="font-mono text-sm bg-slate-100 p-2 rounded">{data.target}</p>
                </div>
                <div>
                  <p className="text-sm text-slate-500 mb-1">IP Addresses (A Records)</p>
                  <div className="flex flex-wrap gap-2">
                    {data.network.ip_addresses.length > 0 ? (
                      data.network.ip_addresses.map((ip: string, i: number) => (
                        <span key={i} className="font-mono text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded border border-blue-100">{ip}</span>
                      ))
                    ) : (
                      <span className="text-sm text-slate-400">Tidak ada data</span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Web Security Card */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <ShieldCheck className="w-5 h-5 text-emerald-500" />
                <h3 className="text-lg font-semibold">Web & Security Stack</h3>
              </div>
              <ul className="space-y-3">
                <li className="flex justify-between items-center text-sm border-b border-slate-50 pb-2">
                  <span className="text-slate-500 flex items-center gap-2"><Server className="w-4 h-4"/> Server</span>
                  <span className="font-medium">{data.web.server_software}</span>
                </li>
                <li className="flex justify-between items-center text-sm border-b border-slate-50 pb-2">
                  <span className="text-slate-500 flex items-center gap-2"><FileKey className="w-4 h-4"/> WAF Detected</span>
                  <span className="font-medium text-emerald-600">{data.web.waf_detected}</span>
                </li>
                <li className="flex justify-between items-center text-sm pb-2">
                  <span className="text-slate-500 flex items-center gap-2"><Activity className="w-4 h-4"/> HTTPS Enabled</span>
                  <span className="font-medium">{data.web.https_enabled ? 'Yes' : 'No'}</span>
                </li>
              </ul>
            </div>

            {/* Placeholder for Advanced Features */}
            <div className="bg-slate-50 p-6 rounded-2xl border border-dashed border-slate-300 md:col-span-2 flex flex-col items-center justify-center text-center py-12">
              <FileKey className="w-8 h-8 text-slate-400 mb-3" />
              <h3 className="text-slate-700 font-medium mb-1">Fitur Lanjutan Membutuhkan API Key</h3>
              <p className="text-sm text-slate-500 max-w-md">
                Fitur seperti Malware Check, Data Breach Lookup, dan Social OSINT memerlukan integrasi pihak ketiga.
              </p>
            </div>

          </div>
        )}
      </main>
    </div>
  );
}
