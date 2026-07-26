"use client";

import { useState } from 'react';
import { Search, Globe, Server, ShieldCheck, Activity, AlertTriangle, Lock, Bug, FileText } from 'lucide-react';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Home() {
  const [searchInput, setSearchInput] = useState('');
  const [target, setTarget] = useState('');

  const { data, error, isLoading } = useSWR(
    target ? `/api/lookup?target=${target}` : null,
    fetcher
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) setTarget(searchInput.trim());
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans selection:bg-blue-200">
      <header className="bg-white border-b border-slate-200 py-4 px-6 md:px-12 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-6 h-6 text-blue-600" />
          <h1 className="text-xl font-bold tracking-tight">RifqyLookup</h1>
        </div>
        <nav className="text-sm font-medium text-slate-500">Advanced OSINT Tool</nav>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        <div className="flex flex-col items-center mb-12">
          <h2 className="text-3xl md:text-4xl font-extrabold mb-4 text-center">Investigasi Mendalam</h2>
          <form onSubmit={handleSearch} className="w-full max-w-2xl relative mt-4">
            <div className="relative flex items-center">
              <Search className="absolute left-4 w-5 h-5 text-slate-400" />
              <input
                type="text"
                placeholder="Masukkan domain (Contoh: vercel.com)"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="w-full pl-12 pr-32 py-4 rounded-xl border border-slate-300 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
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

        {error || data?.error ? (
          <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 flex items-center gap-3 mb-8">
            <AlertTriangle className="w-5 h-5" />
            <p>{data?.error || 'Gagal mengambil data.'}</p>
          </div>
        ) : null}

        {data && !data.error && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in duration-500">
            
            {/* Network & Web Stack */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <Globe className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-semibold">Infrastruktur & Web</h3>
              </div>
              <ul className="space-y-3 text-sm">
                <li className="flex justify-between border-b border-slate-50 pb-2">
                  <span className="text-slate-500">IP Addresses</span>
                  <span className="font-mono">{data.network.ip_addresses[0] || 'N/A'}</span>
                </li>
                <li className="flex justify-between border-b border-slate-50 pb-2">
                  <span className="text-slate-500 flex items-center gap-2"><Server className="w-4 h-4"/> Server</span>
                  <span className="font-medium">{data.web.server_software}</span>
                </li>
                <li className="flex justify-between border-b border-slate-50 pb-2">
                  <span className="text-slate-500 flex items-center gap-2"><ShieldCheck className="w-4 h-4"/> WAF</span>
                  <span className="font-medium">{data.web.waf_detected}</span>
                </li>
              </ul>
            </div>

            {/* SSL/TLS Checker */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <Lock className="w-5 h-5 text-emerald-500" />
                <h3 className="text-lg font-semibold">Sertifikat SSL/TLS</h3>
              </div>
              {data.ssl ? (
                <ul className="space-y-3 text-sm">
                  <li className="flex justify-between border-b border-slate-50 pb-2">
                    <span className="text-slate-500">Status</span>
                    <span className={`font-medium ${data.ssl.valid ? 'text-emerald-600' : 'text-red-600'}`}>
                      {data.ssl.valid ? 'Valid & Trusted' : 'Invalid'}
                    </span>
                  </li>
                  <li className="flex justify-between border-b border-slate-50 pb-2">
                    <span className="text-slate-500">Penerbit (Issuer)</span>
                    <span className="font-medium text-right">{data.ssl.issuer}</span>
                  </li>
                  <li className="flex justify-between pb-2">
                    <span className="text-slate-500">Berlaku Hingga</span>
                    <span className="font-medium">{new Date(data.ssl.validTo).toLocaleDateString('id-ID')}</span>
                  </li>
                </ul>
              ) : (
                <p className="text-sm text-slate-500">Data sertifikat SSL tidak ditemukan.</p>
              )}
            </div>

            {/* VirusTotal Check */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <Bug className="w-5 h-5 text-red-500" />
                <h3 className="text-lg font-semibold">Reputasi & Malware Check</h3>
              </div>
              {data.security.virustotal ? (
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="p-3 bg-red-50 rounded-xl border border-red-100">
                    <p className="text-2xl font-bold text-red-600">{data.security.virustotal.malicious || 0}</p>
                    <p className="text-xs text-slate-600 mt-1">Malicious</p>
                  </div>
                  <div className="p-3 bg-amber-50 rounded-xl border border-amber-100">
                    <p className="text-2xl font-bold text-amber-600">{data.security.virustotal.suspicious || 0}</p>
                    <p className="text-xs text-slate-600 mt-1">Suspicious</p>
                  </div>
                  <div className="p-3 bg-emerald-50 rounded-xl border border-emerald-100">
                    <p className="text-2xl font-bold text-emerald-600">{data.security.virustotal.harmless || 0}</p>
                    <p className="text-xs text-slate-600 mt-1">Harmless</p>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-500">API Key VirusTotal belum dikonfigurasi.</p>
              )}
            </div>

            {/* Robots.txt Extractor */}
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 pb-4">
                <FileText className="w-5 h-5 text-amber-500" />
                <h3 className="text-lg font-semibold">Robots.txt</h3>
              </div>
              {data.files.robots_txt ? (
                <pre className="text-xs bg-slate-900 text-slate-300 p-4 rounded-xl overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto">
                  {data.files.robots_txt}
                </pre>
              ) : (
                <p className="text-sm text-slate-500">File robots.txt tidak ditemukan di target.</p>
              )}
            </div>

          </div>
        )}
      </main>
    </div>
  );
}
