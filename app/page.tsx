"use client";

import { useState, useEffect } from 'react';
import { useTheme } from 'next-themes';
import { 
  Search, Globe, Server, ShieldCheck, Activity, AlertTriangle, Lock, Bug, 
  FileText, MailCheck, Map, Sun, Moon, User, List, Terminal, Code, Info
} from 'lucide-react';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Home() {
  const [searchInput, setSearchInput] = useState('');
  const [target, setTarget] = useState('');
  const [searchMode, setSearchMode] = useState<'domain' | 'username'>('domain');
  
  // Fitur Dark Mode (Auto Tema)
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Menentukan API mana yang dipanggil berdasarkan mode pencarian
  const apiEndpoint = searchMode === 'domain' 
    ? (target ? `/api/lookup?target=${target}` : null) 
    : (target ? `/api/username?username=${target}` : null);

  const { data, error, isLoading } = useSWR(apiEndpoint, fetcher);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) setTarget(searchInput.trim());
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans selection:bg-blue-200 dark:selection:bg-blue-900 transition-colors duration-300">
      
      <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 py-4 px-6 md:px-12 flex items-center justify-between transition-colors duration-300">
        <div className="flex items-center gap-2">
          <Activity className="w-6 h-6 text-blue-600 dark:text-blue-500" />
          <h1 className="text-xl font-bold tracking-tight">RifqyLookup</h1>
        </div>
        <div className="flex items-center gap-6">
          <nav className="hidden md:block text-sm font-medium text-slate-500 dark:text-slate-400">Advanced OSINT Tool</nav>
          
          {/* Tombol Toggle Tema */}
          {mounted && (
            <button 
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
              aria-label="Toggle Dark Mode"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5 text-amber-500" /> : <Moon className="w-5 h-5 text-slate-600" />}
            </button>
          )}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        <div className="flex flex-col items-center mb-12">
          <h2 className="text-3xl md:text-4xl font-extrabold mb-6 text-center">Investigasi Mendalam</h2>
          
          {/* Tab Pemilih Mode Pencarian */}
          <div className="flex bg-slate-200 dark:bg-slate-800 p-1 rounded-xl mb-6">
            <button
              onClick={() => { setSearchMode('domain'); setTarget(''); setSearchInput(''); }}
              className={`flex items-center gap-2 px-6 py-2 rounded-lg text-sm font-medium transition-all ${searchMode === 'domain' ? 'bg-white dark:bg-slate-900 shadow-sm text-blue-600 dark:text-blue-400' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'}`}
            >
              <Globe className="w-4 h-4" /> Domain & IP
            </button>
            <button
              onClick={() => { setSearchMode('username'); setTarget(''); setSearchInput(''); }}
              className={`flex items-center gap-2 px-6 py-2 rounded-lg text-sm font-medium transition-all ${searchMode === 'username' ? 'bg-white dark:bg-slate-900 shadow-sm text-blue-600 dark:text-blue-400' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'}`}
            >
              <User className="w-4 h-4" /> Username (OSINT)
            </button>
          </div>

          <form onSubmit={handleSearch} className="w-full max-w-2xl relative mt-2">
            <div className="relative flex items-center">
              <Search className="absolute left-4 w-5 h-5 text-slate-400" />
              <input
                type="text"
                placeholder={searchMode === 'domain' ? "Masukkan domain (Contoh: vercel.com)" : "Masukkan username (Contoh: rifqy_keren)"}
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="w-full pl-12 pr-32 py-4 rounded-xl border border-slate-300 dark:border-slate-700 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white dark:bg-slate-900 dark:text-white transition-colors"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="absolute right-2 px-6 py-2 bg-slate-900 dark:bg-blue-600 hover:bg-slate-800 dark:hover:bg-blue-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {isLoading ? 'Mencari...' : 'Analisis'}
              </button>
            </div>
          </form>
        </div>

        {error || data?.error ? (
          <div className="p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-xl text-red-600 dark:text-red-400 flex items-center gap-3 mb-8">
            <AlertTriangle className="w-5 h-5" />
            <p>{data?.error || 'Gagal mengambil data.'}</p>
          </div>
        ) : null}

        {/* =========================================
            HASIL PENCARIAN USERNAME (SOCIAL OSINT) 
            ========================================= */}
        {searchMode === 'username' && data && !data.error && data.details && (
          <div className="animate-in fade-in duration-500 space-y-6">
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <h3 className="text-lg font-semibold mb-4 border-b border-slate-100 dark:border-slate-800 pb-4 flex items-center gap-2">
                <User className="w-5 h-5 text-blue-500" /> Hasil Investigasi Username: <span className="font-mono text-blue-600 dark:text-blue-400">@{data.target}</span>
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                {/* Ditemukan */}
                <div>
                  <h4 className="font-medium text-emerald-600 dark:text-emerald-400 mb-3 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" /> Ditemukan ({data.details.found.length})
                  </h4>
                  <ul className="space-y-2">
                    {data.details.found.length > 0 ? data.details.found.map((item: any, i: number) => (
                      <li key={i} className="flex justify-between items-center bg-slate-50 dark:bg-slate-800 p-3 rounded-lg text-sm border border-slate-100 dark:border-slate-700">
                        <span className="font-medium">{item.platform}</span>
                        <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline text-xs">Kunjungi Profil &rarr;</a>
                      </li>
                    )) : (
                      <p className="text-sm text-slate-500 dark:text-slate-400 italic">Tidak ada akun ditemukan.</p>
                    )}
                  </ul>
                </div>

                {/* Tidak Ditemukan / Error */}
                <div>
                  <h4 className="font-medium text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Tidak Ditemukan ({data.details.not_found.length})
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {data.details.not_found.map((item: any, i: number) => (
                      <span key={i} className="text-xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-3 py-1 rounded-full border border-slate-200 dark:border-slate-700">
                        {item.platform}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =========================================
            HASIL PENCARIAN DOMAIN & IP
            ========================================= */}
        {searchMode === 'domain' && data && !data.error && data.network && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-in fade-in duration-500">
            
            {/* Network & Web Stack */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <Globe className="w-5 h-5 text-blue-500" />
                <h3 className="text-lg font-semibold">Infrastruktur & Web</h3>
              </div>
              <ul className="space-y-3 text-sm">
                <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                  <span className="text-slate-500 dark:text-slate-400">IP Addresses</span>
                  <span className="font-mono">{data.network.ip_addresses[0] || 'N/A'}</span>
                </li>
                <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                  <span className="text-slate-500 dark:text-slate-400 flex items-center gap-2"><Server className="w-4 h-4"/> Server</span>
                  <span className="font-medium">{data.web.server_software}</span>
                </li>
                <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                  <span className="text-slate-500 dark:text-slate-400 flex items-center gap-2"><ShieldCheck className="w-4 h-4"/> WAF</span>
                  <span className="font-medium">{data.web.waf_detected}</span>
                </li>
                <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                  <span className="text-slate-500 dark:text-slate-400 flex items-center gap-2"><Map className="w-4 h-4"/> Sitemap.xml</span>
                  <span className={`font-medium ${data.web.has_sitemap ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}`}>
                    {data.web.has_sitemap ? 'Ditemukan' : 'Tidak Ditemukan'}
                  </span>
                </li>
              </ul>
            </div>

            {/* Subdomain Enumeration (UI Baru) */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <List className="w-5 h-5 text-purple-500" />
                <h3 className="text-lg font-semibold">Subdomain Terdeteksi</h3>
              </div>
              {data.subdomains ? (
                <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto">
                  {data.subdomains.length > 0 ? data.subdomains.map((sub: string, i: number) => (
                    <span key={i} className="font-mono text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-2 py-1 rounded border border-slate-200 dark:border-slate-700">
                      {sub}
                    </span>
                  )) : (
                    <p className="text-sm text-slate-500">Tidak ada subdomain yang ditemukan.</p>
                  )}
                </div>
              ) : (
                <p className="text-sm text-slate-400 italic">Menunggu update backend...</p>
              )}
            </div>

            {/* Email Security (SPF & DMARC) */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <MailCheck className="w-5 h-5 text-indigo-500" />
                <h3 className="text-lg font-semibold">Keamanan Email</h3>
              </div>
              <div className="space-y-4 text-sm">
                <div>
                  <p className="text-slate-500 dark:text-slate-400 mb-1 flex justify-between">
                    <span>SPF Record</span>
                    <span className={data.email_security.spf ? 'text-emerald-600 dark:text-emerald-400 font-medium' : 'text-red-500 font-medium'}>
                      {data.email_security.spf ? 'Terlindungi' : 'Rentan'}
                    </span>
                  </p>
                  <p className="font-mono text-xs bg-slate-50 dark:bg-slate-950 p-2 rounded border border-slate-100 dark:border-slate-800 break-all text-slate-700 dark:text-slate-300">
                    {data.email_security.spf || 'Tidak ada record SPF. Domain bisa dipalsukan.'}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500 dark:text-slate-400 mb-1 flex justify-between">
                    <span>DMARC Record</span>
                    <span className={data.email_security.dmarc ? 'text-emerald-600 dark:text-emerald-400 font-medium' : 'text-red-500 font-medium'}>
                      {data.email_security.dmarc ? 'Terlindungi' : 'Rentan'}
                    </span>
                  </p>
                  <p className="font-mono text-xs bg-slate-50 dark:bg-slate-950 p-2 rounded border border-slate-100 dark:border-slate-800 break-all text-slate-700 dark:text-slate-300">
                    {data.email_security.dmarc || 'Tidak ada record DMARC.'}
                  </p>
                </div>
              </div>
            </div>

            {/* SSL/TLS Checker */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <Lock className="w-5 h-5 text-emerald-500" />
                <h3 className="text-lg font-semibold">Sertifikat SSL/TLS</h3>
              </div>
              {data.ssl ? (
                <ul className="space-y-3 text-sm">
                  <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Status</span>
                    <span className={`font-medium ${data.ssl.valid ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                      {data.ssl.valid ? 'Valid & Trusted' : 'Invalid'}
                    </span>
                  </li>
                  <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Penerbit (Issuer)</span>
                    <span className="font-medium text-right truncate ml-4">{data.ssl.issuer}</span>
                  </li>
                  <li className="flex justify-between pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Berlaku Hingga</span>
                    <span className="font-medium">{new Date(data.ssl.validTo).toLocaleDateString('id-ID')}</span>
                  </li>
                </ul>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">Data sertifikat SSL tidak ditemukan.</p>
              )}
            </div>

            {/* Tech Stack & Port Scanner (UI Baru) */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <Code className="w-5 h-5 text-pink-500" />
                <h3 className="text-lg font-semibold">Tech Stack & Port</h3>
              </div>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-2 flex items-center gap-2"><Terminal className="w-4 h-4"/> Port Terbuka</p>
                  <div className="flex flex-wrap gap-2">
                    {data.network.open_ports ? data.network.open_ports.map((port: number, i: number) => (
                       <span key={i} className="font-mono text-xs bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 px-2 py-1 rounded border border-emerald-200 dark:border-emerald-800">
                         Port {port}
                       </span>
                    )) : <span className="text-xs text-slate-400 italic">Menunggu update backend...</span>}
                  </div>
                </div>
                <div>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-2 flex items-center gap-2"><Code className="w-4 h-4"/> Teknologi Terdeteksi</p>
                  <div className="flex flex-wrap gap-2">
                    {data.web.tech_stack ? data.web.tech_stack.map((tech: string, i: number) => (
                       <span key={i} className="font-medium text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-2 py-1 rounded border border-slate-200 dark:border-slate-700">
                         {tech}
                       </span>
                    )) : <span className="text-xs text-slate-400 italic">Menunggu update backend...</span>}
                  </div>
                </div>
              </div>
            </div>

            {/* WHOIS Lookup (UI Baru) */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <Info className="w-5 h-5 text-cyan-500" />
                <h3 className="text-lg font-semibold">Informasi WHOIS</h3>
              </div>
              {data.whois ? (
                <ul className="space-y-3 text-sm">
                  <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Registrar</span>
                    <span className="font-medium">{data.whois.registrar || 'N/A'}</span>
                  </li>
                  <li className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Dibuat Pada</span>
                    <span className="font-medium">{data.whois.creation_date || 'N/A'}</span>
                  </li>
                  <li className="flex justify-between pb-2">
                    <span className="text-slate-500 dark:text-slate-400">Kadaluarsa (Expired)</span>
                    <span className="font-medium">{data.whois.expiration_date || 'N/A'}</span>
                  </li>
                </ul>
              ) : (
                <p className="text-sm text-slate-400 italic">Menunggu update backend...</p>
              )}
            </div>

            {/* VirusTotal Check */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800 md:col-span-2">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <Bug className="w-5 h-5 text-red-500" />
                <h3 className="text-lg font-semibold">Reputasi & Malware Check</h3>
              </div>
              {data.security.virustotal ? (
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-xl border border-red-100 dark:border-red-900/50">
                    <p className="text-3xl font-bold text-red-600 dark:text-red-400">{data.security.virustotal.malicious || 0}</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">Malicious</p>
                  </div>
                  <div className="p-4 bg-amber-50 dark:bg-amber-900/20 rounded-xl border border-amber-100 dark:border-amber-900/50">
                    <p className="text-3xl font-bold text-amber-600 dark:text-amber-400">{data.security.virustotal.suspicious || 0}</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">Suspicious</p>
                  </div>
                  <div className="p-4 bg-emerald-50 dark:bg-emerald-900/20 rounded-xl border border-emerald-100 dark:border-emerald-900/50">
                    <p className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">{data.security.virustotal.harmless || 0}</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">Harmless</p>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">API Key VirusTotal belum dikonfigurasi.</p>
              )}
            </div>

            {/* Robots.txt Extractor */}
            <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800 md:col-span-2">
              <div className="flex items-center gap-3 mb-6 border-b border-slate-100 dark:border-slate-800 pb-4">
                <FileText className="w-5 h-5 text-amber-500" />
                <h3 className="text-lg font-semibold">Robots.txt Extractor</h3>
              </div>
              {data.files.robots_txt ? (
                <pre className="text-xs bg-slate-900 dark:bg-black text-slate-300 p-4 rounded-xl overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto border dark:border-slate-800">
                  {data.files.robots_txt}
                </pre>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">File robots.txt tidak ditemukan di target.</p>
              )}
            </div>

          </div>
        )}
      </main>
    </div>
  );
}
