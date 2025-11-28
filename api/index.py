from flask import Flask, request, jsonify
from flask_cors import CORS
import dns.resolver
import requests
import whois # Library untuk whois lookup
import socket

app = Flask(__name__)
# Izinkan semua domain mengakses API ini (atau ganti '*' dengan domain github pages kamu nanti)
CORS(app) 

# --- Fungsi Helper ---

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            records[r_type] = [r.to_text() for r in answers]
        except:
            records[r_type] = []
    return records

def get_subdomains(domain):
    # Menggunakan crt.sh seperti sebelumnya
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            for entry in resp.json():
                name_value = entry['name_value']
                for sub in name_value.split('\n'):
                    if '*' not in sub: subdomains.add(sub)
    except:
        pass
    return list(subdomains)[:15] # Batasi 15 saja biar cepat

def get_geoip(domain):
    try:
        # Dapatkan IP dulu
        ip = socket.gethostbyname(domain)
        # Gunakan API publik ip-api.com (gratis untuk non-komersial)
        resp = requests.get(f"http://ip-api.com/json/{ip}")
        return resp.json()
    except:
        return {"error": "Gagal mengambil data GeoIP"}

def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        # Konversi datetime objects ke string agar bisa jadi JSON
        return str(w)
    except:
        return "Data Whois diproteksi atau tidak ditemukan."

# --- Route Utama ---

@app.route('/api/lookup', methods=['POST'])
def lookup():
    data = request.json
    raw_domain = data.get('domain', '')
    
    # Bersihkan input domain
    domain = raw_domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    if not domain:
        return jsonify({'error': 'Domain tidak valid'}), 400

    # Jalankan semua fungsi
    dns_data = get_dns_records(domain)
    sub_data = get_subdomains(domain)
    geo_data = get_geoip(domain)
    whois_data = get_whois_data(domain)

    return jsonify({
        'domain': domain,
        'dns': dns_data,
        'subdomains': sub_data,
        'geoip': geo_data,
        'whois': whois_data
    })

# Handler untuk Vercel (PENTING)
if __name__ == '__main__':
    app.run(debug=True)
