import { NextResponse } from 'next/server';
import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';

// Fungsi bantuan untuk mengecek SSL/TLS
const checkSSL = (host: string): Promise<any> => {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve({
        valid: socket.authorized,
        issuer: cert.issuer?.O || 'Unknown',
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
      });
    });
    socket.on('error', () => resolve(null));
  });
};

// FITUR BARU: Fungsi bantuan untuk Port Scanner (dengan timeout super cepat)
const checkPort = (port: number, host: string): Promise<number | null> => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1500); // Batas maksimal 1.5 detik per port agar Vercel tidak error
    
    socket.on('connect', () => {
      socket.destroy();
      resolve(port);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });
    
    socket.connect(port, host);
  });
};

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('target');

  if (!target) {
    return NextResponse.json({ error: 'Target domain atau IP wajib diisi.' }, { status: 400 });
  }

  const cleanTarget = target.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0];

  try {
    // 1. Network Recon (DNS)
    const recordsA = await dns.resolve4(cleanTarget).catch(() => []);
    const recordsTXTRaw = await dns.resolveTxt(cleanTarget).catch(() => []);
    const txtStrings = recordsTXTRaw.map(txt => txt.join(''));
    
    // 2. Email Security (SPF & DMARC)
    const spfRecord = txtStrings.find(txt => txt.startsWith('v=spf1')) || null;
    let dmarcRecord = null;
    try {
      const dmarcTXT = await dns.resolveTxt(`_dmarc.${cleanTarget}`);
      dmarcRecord = dmarcTXT.map(txt => txt.join('')).find(txt => txt.startsWith('v=DMARC1')) || null;
    } catch (e) {
      // DMARC tidak ditemukan
    }

    // 3. HTTP Headers, Tech Stack, Robots.txt & Sitemap
    let headers: Record<string, string> = {};
    let isHttps = false;
    let robotsTxt = null;
    let hasSitemap = false;
    let techStack: string[] = []; // FITUR BARU: Penampung Tech Stack
    
    try {
      // Menggunakan GET untuk mengambil HTML web demi mendeteksi Tech Stack
      const response = await fetch(`https://${cleanTarget}`, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(3000) });
      headers = Object.fromEntries(response.headers.entries());
      isHttps = true;

      // FITUR BARU: Deteksi Tech Stack sederhana melalui kode HTML
      const html = await response.text();
      const htmlLower = html.toLowerCase();
      
      if (htmlLower.includes('wp-content')) techStack.push('WordPress');
      if (htmlLower.includes('id="__next"') || htmlLower.includes('/_next/')) techStack.push('Next.js');
      else if (htmlLower.includes('react') || htmlLower.includes('id="root"')) techStack.push('React');
      if (htmlLower.includes('laravel_session') || htmlLower.includes('laravel')) techStack.push('Laravel');
      if (htmlLower.includes('bootstrap')) techStack.push('Bootstrap');
      if (htmlLower.includes('tailwind')) techStack.push('Tailwind CSS');
      if (headers['x-powered-by']) techStack.push(`${headers['x-powered-by']}`);
      if (techStack.length === 0) techStack.push('Tidak Terdeteksi');
      
      const robotsRes = await fetch(`https://${cleanTarget}/robots.txt`, { signal: AbortSignal.timeout(2000) });
      if (robotsRes.ok) {
        const text = await robotsRes.text();
        robotsTxt = text.slice(0, 500) + (text.length > 500 ? '\n...[terpotong]' : '');
      }

      const sitemapRes = await fetch(`https://${cleanTarget}/sitemap.xml`, { method: 'HEAD', signal: AbortSignal.timeout(2000) });
      if (sitemapRes.ok) hasSitemap = true;
    } catch (e) {
      // Fallback
    }

    const server = headers['server'] || 'Tidak Terdeteksi';
    const wafDetected = String(server).toLowerCase().includes('cloudflare') ? 'Cloudflare' : 'Tidak Terdeteksi';

    // 4. SSL/TLS Checker
    const sslInfo = await checkSSL(cleanTarget);

    // 5. VirusTotal
    let virustotal = null;
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtKey) {
      try {
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${cleanTarget}`, {
          headers: { 'x-apikey': vtKey }
        });
        if (vtRes.ok) {
          const vtData = await vtRes.json();
          const stats = vtData.data.attributes.last_analysis_stats;
          virustotal = { malicious: stats.malicious, suspicious: stats.suspicious, harmless: stats.harmless };
        }
      } catch (e) {
        virustotal = { error: "Gagal menjangkau API VirusTotal" };
      }
    }

    // FITUR BARU: Subdomain, WHOIS, dan Port Scanner (Dieksekusi serentak agar cepat)
    // PERBAIKAN: Menambahkan Cadangan (Fallback API), membersihkan *. dan menambah timeout
    const crtPromise = fetch(`https://crt.sh/?q=%25.${cleanTarget}&output=json`, { signal: AbortSignal.timeout(6000) })
      .then(res => res.ok ? res.json() : [])
      .then(data => {
         if (!Array.isArray(data) || data.length === 0) throw new Error('Data crt.sh kosong');
         
         const subs: string[] = data.map((entry: any) => {
           const val = String(entry.name_value || entry.common_name || "");
           return val.split('\n');
         }).flat();
         
         const cleanedSubs = subs
           .map(sub => sub.replace(/^\*\./, '').toLowerCase().trim())
           .filter(sub => sub.endsWith(cleanTarget) && sub !== cleanTarget);
           
         const uniqueSubs = Array.from(new Set(cleanedSubs)).slice(0, 30);
         if (uniqueSubs.length === 0) throw new Error('Tidak ada subdomain valid');
         return uniqueSubs;
      })
      .catch(async () => {
         // API CADANGAN JIKA CRT.SH GAGAL: HackerTarget
         try {
           const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${cleanTarget}`, { signal: AbortSignal.timeout(4000) });
           if (!htRes.ok) return [] as string[];
           const text = await htRes.text();
           
           if (text.includes('error') || text.includes('API count exceeded')) return [] as string[];
           
           const htSubs = text.split('\n')
             .map(line => line.split(',')[0].toLowerCase().trim())
             .filter(sub => sub.endsWith(cleanTarget) && sub !== cleanTarget);
             
           return Array.from(new Set(htSubs)).slice(0, 30);
         } catch (e) {
           return [] as string[];
         }
      });

    const whoisPromise = fetch(`https://rdap.org/domain/${cleanTarget}`, { signal: AbortSignal.timeout(4000) })
      .then(res => res.ok ? res.json() : null)
      .then(data => {
         if (!data) return null;
         const registrarEnt = data.entities?.find((e: any) => e.roles?.includes('registrar'));
         const registrarName = registrarEnt?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'Unknown';
         const events = data.events || [];
         const created = events.find((e: any) => e.eventAction === 'registration')?.eventDate;
         const expired = events.find((e: any) => e.eventAction === 'expiration')?.eventDate;
         return {
           registrar: registrarName,
           creation_date: created ? new Date(created).toLocaleDateString('id-ID') : 'N/A',
           expiration_date: expired ? new Date(expired).toLocaleDateString('id-ID') : 'N/A'
         };
      }).catch(() => null);

    const portsToCheck = [21, 22, 80, 443, 3306];
    const portPromises = Promise.all(portsToCheck.map(port => checkPort(port, cleanTarget)));

    // Menunggu hasil eksekusi serentak
    const [subdomains, whois, openPortsRaw] = await Promise.all([crtPromise, whoisPromise, portPromises]);
    const open_ports = openPortsRaw.filter(p => p !== null);

    return NextResponse.json({
      target: cleanTarget,
      subdomains: subdomains,
      whois: whois,
      network: { 
        ip_addresses: recordsA,
        open_ports: open_ports 
      },
      email_security: { spf: spfRecord, dmarc: dmarcRecord },
      web: { 
        https_enabled: isHttps, 
        server_software: server, 
        waf_detected: wafDetected, 
        has_sitemap: hasSitemap,
        tech_stack: techStack
      },
      ssl: sslInfo,
      files: { robots_txt: robotsTxt },
      security: { virustotal }
    });

  } catch (error) {
    return NextResponse.json({ error: 'Gagal melakukan investigasi pada target tersebut.' }, { status: 500 });
  }
}
