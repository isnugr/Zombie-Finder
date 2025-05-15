# Zombie Scanner

Zombie Scanner adalah alat untuk mendeteksi layanan UDP pada host yang rentan terhadap serangan amplifikasi/refleksi (amplification/reflection). Alat ini mendukung multi-threading adaptif, penyimpanan hasil ke database MySQL/MariaDB, dan dapat dilanjutkan jika proses terputus.

## Fitur Utama
- Scan UDP amplification vector (DNS, NTP, cLDAP, dll)
- Input host dari file (1 IP per baris, mendukung CIDR)
- Penyimpanan hasil ke database MySQL/MariaDB
- Status scan per host (pending, scanning, vulnerable, not vulnerable)
- Paralelisme adaptif (otomatis menyesuaikan jumlah worker sesuai load CPU)
- Bisa dihentikan dengan Ctrl+C (graceful shutdown)
- Progress bar saat insert host

## Instalasi
1. **Clone repo & install dependency**
   ```sh
   git clone <repo-anda>
   cd zombie-scanner
   go mod tidy
   ```
   Dependency utama:
   - github.com/go-sql-driver/mysql
   - github.com/schollz/progressbar/v3
2. **Build (opsional)**
   ```sh
   go build -o zombie-scanner main.go
   ```

## Cara Penggunaan
1. **Siapkan file IP** (misal: `hosts.txt`), 1 IP per baris:
   ```
   1.2.3.4
   5.6.7.8
   192.168.1.0/24
   # Baris komentar akan diabaikan
   ```
2. **Jalankan scanner**
   ```sh
   go run main.go --hostsfile hosts.txt --vectors all --db "user:password@tcp(127.0.0.1:3306)/zombie"
   # atau jika sudah build
   ./zombie-scanner --hostsfile hosts.txt --vectors all --db "user:password@tcp(127.0.0.1:3306)/zombie"
   ```
   Opsi lain:
   - `--timeout 500` (atur timeout per paket UDP dalam ms)
   - `--vectors DNS_A,NTP` (hanya scan vektor tertentu)
   - `--vectors display` (tampilkan daftar vektor yang didukung)
   - `--workers 20` (atur jumlah worker)

3. **Hentikan dengan Ctrl+C** jika ingin membatalkan scan.

## Output & Database
- Hasil scan disimpan ke database MySQL/MariaDB sesuai parameter `--db`.
- Tabel utama:
  - `hosts`: daftar IP (VARBINARY(16)) dan status scan (`pending`, `scanning`, `vulnerable`, `not vulnerable`)
  - `scan_results`: hasil sukses (1 baris per kombinasi host-vektor yang open)

### Contoh Query Hasil
- Semua hasil sukses untuk satu host (gunakan fungsi INET6_NTOA untuk konversi IP):
  ```sql
  SELECT * FROM scan_results WHERE host = '1.2.3.4';
  -- atau untuk hosts:
  SELECT * FROM hosts WHERE INET6_NTOA(ip) = '1.2.3.4';
  ```
- Semua host yang open pada vektor NTP:
  ```sql
  SELECT * FROM scan_results WHERE vector = 'NTP';
  ```
- Semua host yang statusnya vulnerable:
  ```sql
  SELECT INET6_NTOA(ip) as ip, status FROM hosts WHERE status = 'vulnerable';
  ```

## Catatan Penting
- **Gunakan hanya pada sistem yang Anda miliki atau punya izin eksplisit!**
- Penggunaan tanpa izin bisa melanggar hukum.

## Lisensi
MIT 