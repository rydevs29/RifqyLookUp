# RifqyLookup - Advanced OSINT & Reconnaissance Tool

[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat&logo=next.js)](https://nextjs.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Vercel](https://img.shields.io/badge/Deployed_on-Vercel-black?style=flat&logo=vercel)](https://vercel.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**RifqyLookup** adalah sebuah *web-based tool* intelijen sumber terbuka (OSINT) dan alat *reconnaissance* canggih yang dirancang untuk melakukan investigasi mendalam terhadap Domain, IP Address, dan jejak digital Username. Dibangun menggunakan arsitektur modern Next.js App Router, alat ini mampu melakukan pemindaian jaringan dan analisis keamanan secara *real-time* langsung dari peramban (browser).

**Live Demo:** [Click Here](https://lookup.rifqydev.my.id)

---

## Fitur Utama

Aplikasi ini membagi investigasinya ke dalam dua mode utama: **Domain & IP Recon** dan **Social OSINT (Username)**.
### Mode Domain & IP
- **Infrastruktur & Web:** Melacak IP Address, mendeteksi Web Application Firewall (WAF) seperti Cloudflare, dan mengecek keberadaan `sitemap.xml`.
- **Subdomain Enumeration:** Membongkar subdomain tersembunyi yang terkait dengan target secara asinkronus (menggunakan integrasi `crt.sh` dan HackerTarget).
- **Tech Stack & Port Scanner:** Mendeteksi teknologi di balik website (React, Next.js, WordPress, Laravel, dll) serta memindai *open ports* krusial (21, 22, 80, 443, 3306) menggunakan modul TCP socket.
- **Keamanan Email (Anti-Spoofing):** Memvalidasi konfigurasi perlindungan email dari spam/spoofing melalui pengecekan SPF & DMARC DNS records.
- **Sertifikat SSL/TLS:** Memeriksa status validitas, penerbit (Issuer), dan tanggal kedaluwarsa sertifikat keamanan enkripsi web target.
- **WHOIS Lookup:** Menampilkan informasi *registrar* dan tanggal aktivasi/kedaluwarsa domain menggunakan protokol RDAP.
- **Reputasi & Malware Check:** Terintegrasi langsung dengan API VirusTotal untuk mendeteksi apakah domain terindikasi berbahaya (*Malicious/Suspicious/Harmless*).
- **Robots.txt Extractor:** Menarik dan menampilkan aturan perayapan (*crawling*) mesin pencari dari target web.

### Mode Username (Social OSINT)
- **Cross-Platform Username Tracker:** Melacak ketersediaan dan keberadaan sebuah *username* di berbagai platform digital dan media sosial (GitHub, Reddit, Pinterest, SoundCloud, Vimeo, dll) secara paralel (serentak) untuk performa tingkat tinggi.

---

## Tech Stack (Teknologi yang Digunakan)

- **Frontend & Backend Framework:** [Next.js 14](https://nextjs.org/) (App Router)
- **Desain & UI:** [Tailwind CSS](https://tailwindcss.com/) dengan ikon dari [Lucide React](https://lucide.dev/)
- **Bahasa Pemrograman:** [TypeScript](https://www.typescriptlang.org/)
- **State Management & Data Fetching:** [SWR](https://swr.vercel.app/)
- **Backend Native Modules:** `dns` (Domain Name System), `tls` (Transport Layer Security), `net` (Network TCP Sockets)
- **Tema:** Dukungan Auto Dark/Light Mode menggunakan `next-themes`
- **Deployment & Hosting:** [Vercel](https://vercel.com/) (Serverless Functions)
