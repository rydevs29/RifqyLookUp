import { NextResponse } from 'next/server';
import dns from 'dns/promises';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const target = searchParams.get('target');

  if (!target) {
    return NextResponse.json({ error: 'Target domain atau IP wajib diisi.' }, { status: 400 });
  }

  // Membersihkan input (hapus http:// atau https:// jika ada)
  const cleanTarget = target.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split('/')[0];

  try {
    // 1. Informasi DNS & IP (Network Recon)
    const recordsA = await dns.resolve4(cleanTarget).catch(() => []);
    const recordsMX = await dns.resolveMx(cleanTarget).catch(() => []);
    const recordsTXT = await dns.resolveTxt(cleanTarget).catch(() => []);

    // 2. HTTP Headers & Basic Tech Stack (Web Recon)
    let headers = {};
    let isHttps = false;
    
    try {
      const response = await fetch(`https://${cleanTarget}`, { method: 'HEAD', redirect: 'follow' });
      headers = Object.fromEntries(response.headers.entries());
      isHttps = true;
    } catch (e) {
      // Fallback ke HTTP jika HTTPS gagal
      const response = await fetch(`http://${cleanTarget}`, { method: 'HEAD', redirect: 'follow' }).catch(() => null);
      if (response) headers = Object.fromEntries(response.headers.entries());
    }

    // Ekstraksi Keamanan Dasar dari Header
    const server = headers['server' as keyof typeof headers] || 'Tidak Terdeteksi';
    const xPoweredBy = headers['x-powered-by' as keyof typeof headers] || 'Tidak Terdeteksi';
    
    // Pengecekan WAF & CORS Sederhana dari Header
    const corsStatus = headers['access-control-allow-origin' as keyof typeof headers] ? 'Dikonfigurasi' : 'Tidak Dikonfigurasi/Terbuka';
    const hasCloudflare = server.toString().toLowerCase().includes('cloudflare');

    return NextResponse.json({
      target: cleanTarget,
      network: {
        ip_addresses: recordsA,
        mx_records: recordsMX,
        txt_records: recordsTXT.map(txt => txt.join(' ')), // Berguna untuk cek SPF/DMARC nanti
      },
      web: {
        https_enabled: isHttps,
        server_software: server,
        tech_stack: xPoweredBy,
        cors_status: corsStatus,
        waf_detected: hasCloudflare ? 'Cloudflare' : 'Tidak Terdeteksi (via Header)',
        raw_headers: headers,
      }
    });

  } catch (error) {
    return NextResponse.json({ error: 'Gagal melakukan investigasi pada target tersebut.' }, { status: 500 });
  }
}
