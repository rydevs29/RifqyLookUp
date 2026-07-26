import { NextResponse } from 'next/server';

// Daftar platform OSINT yang memiliki HTTP status responsif (200 OK / 404 Not Found)
const platforms = [
  { name: 'GitHub', url: 'https://github.com/{}' },
  { name: 'Reddit', url: 'https://www.reddit.com/user/{}/about.json' }, // API JSON lebih akurat untuk Reddit
  { name: 'Pinterest', url: 'https://www.pinterest.com/{}/' },
  { name: 'SoundCloud', url: 'https://soundcloud.com/{}' },
  { name: 'Vimeo', url: 'https://vimeo.com/{}' },
  { name: 'Dev.to', url: 'https://dev.to/{}' },
  { name: 'Wattpad', url: 'https://www.wattpad.com/user/{}' },
  { name: 'Blogger', url: 'https://{}.blogspot.com/' }
];

// Fungsi asinkronus untuk mengecek masing-masing platform
async function checkUsername(platform: typeof platforms[0], username: string) {
  const targetUrl = platform.url.replace('{}', username);
  
  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        // Menyamar sebagai browser PC biasa agar tidak diblokir oleh anti-bot
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
      },
      // Timeout 5 detik agar tidak membuat Vercel limit error (10 detik max)
      signal: AbortSignal.timeout(5000) 
    });

    // Khusus Reddit (karena kita fetch about.json), ubah URL aslinya untuk dikembalikan ke UI
    const displayUrl = platform.name === 'Reddit' ? `https://www.reddit.com/user/${username}` : targetUrl;

    if (response.status === 200) {
      return { platform: platform.name, url: displayUrl, status: 'FOUND' };
    } else {
      return { platform: platform.name, url: displayUrl, status: 'NOT_FOUND' };
    }
  } catch (error) {
    // Menangkap error jika timeout atau jaringan ditolak
    return { platform: platform.name, url: targetUrl, status: 'ERROR' };
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const username = searchParams.get('username');

  if (!username) {
    return NextResponse.json({ error: 'Username target wajib diisi.' }, { status: 400 });
  }

  // Membersihkan username dari karakter ilegal (hanya izinkan huruf, angka, underscore, strip)
  const cleanUsername = username.trim().replace(/[^a-zA-Z0-9_-]/g, '');

  try {
    // Menjalankan semua pencarian secara paralel agar super cepat
    const checkPromises = platforms.map(platform => checkUsername(platform, cleanUsername));
    const results = await Promise.all(checkPromises);

    // Mengelompokkan hasil agar Frontend mudah merendernya
    const found = results.filter(r => r.status === 'FOUND');
    const notFound = results.filter(r => r.status === 'NOT_FOUND');
    const errors = results.filter(r => r.status === 'ERROR');

    return NextResponse.json({
      target: cleanUsername,
      summary: {
        total_checked: platforms.length,
        found_count: found.length,
      },
      details: {
        found,
        not_found: notFound,
        errors
      }
    });

  } catch (error) {
    return NextResponse.json({ error: 'Terjadi kesalahan sistem saat melacak username.' }, { status: 500 });
  }
}
