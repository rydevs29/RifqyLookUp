import { NextResponse } from 'next/server';
import dns from 'dns/promises';
import tls from 'tls';

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

    // 3. HTTP Headers, Robots.txt & Sitemap
    let headers = {};
    let isHttps = false;
    let robotsTxt = null;
    let hasSitemap = false;
    
    try {
      const response = await fetch(`https://${cleanTarget}`, { method: 'HEAD', redirect: 'follow' });
      headers = Object.fromEntries(response.headers.entries());
      isHttps = true;
      
      const robotsRes = await fetch(`https://${cleanTarget}/robots.txt`);
      if (robotsRes.ok) {
        const text = await robotsRes.text();
        robotsTxt = text.slice(0, 500) + (text.length > 500 ? '\n...[terpotong]' : '');
      }

      const sitemapRes = await fetch(`https://${cleanTarget}/sitemap.xml`, { method: 'HEAD' });
      if (sitemapRes.ok) hasSitemap = true;
    } catch (e) {
      // Fallback
    }

    const server = headers['server' as keyof typeof headers] || 'Tidak Terdeteksi';
    const wafDetected = server.toString().toLowerCase().includes('cloudflare') ? 'Cloudflare' : 'Tidak Terdeteksi';

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

    return NextResponse.json({
      target: cleanTarget,
      network: { ip_addresses: recordsA },
      email_security: { spf: spfRecord, dmarc: dmarcRecord },
      web: { https_enabled: isHttps, server_software: server, waf_detected: wafDetected, has_sitemap: hasSitemap },
      ssl: sslInfo,
      files: { robots_txt: robotsTxt },
      security: { virustotal }
    });

  } catch (error) {
    return NextResponse.json({ error: 'Gagal melakukan investigasi pada target tersebut.' }, { status: 500 });
  }
}
