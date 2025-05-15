package main

import (
	"bufio"
	"database/sql"
	"net"
	"os"
	"strings"

	"github.com/schollz/progressbar/v3"
)

func initDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Fungsi inisialisasi semua tabel
func initAllTables(db *sql.DB) error {
	if err := initDBTables(db); err != nil {
		return err
	}
	if err := initHostsTable(db); err != nil {
		return err
	}
	return nil
}

// Pindahkan CREATE TABLE scan_results ke fungsi baru
func initDBTables(db *sql.DB) error {
	dropTable := `DROP TABLE IF EXISTS scan_results;`
	_, err := db.Exec(dropTable)
	if err != nil {
		return err
	}
	createTable := `CREATE TABLE scan_results (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		host TEXT,
		port INTEGER,
		vector TEXT,
		hitrate TEXT,
		ampfactor TEXT,
		latency TEXT
	);`
	_, err = db.Exec(createTable)
	return err
}

func insertResult(db *sql.DB, result ScanResult) error {
	_, err := db.Exec(`INSERT INTO scan_results (host, port, vector, hitrate, ampfactor, latency) VALUES (?, ?, ?, ?, ?, ?)`,
		result.Host, result.Port, result.Name, result.HitRate, result.AmpFactor, result.Latency)
	return err
}

// Tambahkan fungsi untuk inisialisasi tabel hosts dan batch insert
func initHostsTable(db *sql.DB) error {
	dropTable := `DROP TABLE IF EXISTS hosts;`
	_, err := db.Exec(dropTable)
	if err != nil {
		return err
	}
	createTable := `CREATE TABLE hosts (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		ip VARBINARY(16) UNIQUE,
		status ENUM('pending','scanning','vulnerable','not vulnerable') DEFAULT 'pending',
		INDEX idx_status (status)
	);`
	_, err = db.Exec(createTable)
	return err
}

// Tambahkan fungsi cleanup untuk host status scanning dan scan_results terkait
func cleanupHostsAndResults(db *sql.DB) error {
	// Ambil semua IP dengan status scanning
	rows, err := db.Query("SELECT ip FROM hosts WHERE status = 'scanning'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var scanningIPs []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return err
		}
		scanningIPs = append(scanningIPs, ip)
	}

	// Update status host menjadi pending
	if len(scanningIPs) > 0 {
		_, err := db.Exec("UPDATE hosts SET status = 'pending' WHERE status = 'scanning'")
		if err != nil {
			return err
		}
		// Hapus scan_results untuk IP-IP tersebut
		for _, ip := range scanningIPs {
			_, err := db.Exec("DELETE FROM scan_results WHERE host = ?", ip)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func insertHostsFromFile(db *sql.DB, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Hitung total IP valid untuk logging
	total := 0
	scanCount, _ := os.Open(path)
	defer scanCount.Close()
	scannerCount := bufio.NewScanner(scanCount)
	for scannerCount.Scan() {
		ip := strings.TrimSpace(scannerCount.Text())
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		if strings.Contains(ip, "/") {
			_, ipnet, err := net.ParseCIDR(ip)
			if err == nil {
				ones, bits := ipnet.Mask.Size()
				count := 1 << (bits - ones)
				total += count
			}
		} else {
			total++
		}
	}

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Insert Hosts"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(20),
		progressbar.OptionClearOnFinish(),
	)

	batchSize := 1024
	batchIPs := make([]string, 0, batchSize)
	inserted := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		if strings.Contains(ip, "/") {
			ipAddr, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				continue
			}
			for ip := ipAddr.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				ipCopy := make(net.IP, len(ip))
				copy(ipCopy, ip)
				batchIPs = append(batchIPs, ipCopy.String())
				if len(batchIPs) >= batchSize {
					tx, err := db.Begin()
					if err != nil {
						return err
					}
					if err := insertIPBatch(tx, batchIPs); err != nil {
						tx.Rollback()
						return err
					}
					if err := tx.Commit(); err != nil {
						return err
					}
					inserted += len(batchIPs)
					bar.Add(len(batchIPs))
					batchIPs = batchIPs[:0]
				}
			}
		} else {
			batchIPs = append(batchIPs, ip)
			if len(batchIPs) >= batchSize {
				tx, err := db.Begin()
				if err != nil {
					return err
				}
				if err := insertIPBatch(tx, batchIPs); err != nil {
					tx.Rollback()
					return err
				}
				if err := tx.Commit(); err != nil {
					return err
				}
				inserted += len(batchIPs)
				bar.Add(len(batchIPs))
				batchIPs = batchIPs[:0]
			}
		}
	}
	// Insert sisa batch
	if len(batchIPs) > 0 {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := insertIPBatch(tx, batchIPs); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		inserted += len(batchIPs)
		bar.Add(len(batchIPs))
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	bar.Finish()
	return nil
}

// Helper untuk increment IP
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// Helper untuk batch insert
func insertIPBatch(tx *sql.Tx, ips []string) error {
	placeholders := make([]string, len(ips))
	args := make([]interface{}, len(ips))
	for i, ip := range ips {
		placeholders[i] = "(?)"
		args[i] = net.ParseIP(ip)
	}
	query := "INSERT IGNORE INTO hosts (ip) VALUES " + strings.Join(placeholders, ",")
	_, err := tx.Exec(query, args...)
	return err
}

func updateHostStatus(db *sql.DB, ip, status string) error {
	_, err := db.Exec(`UPDATE hosts SET status = ? WHERE ip = ?`, status, net.ParseIP(ip))
	return err
}

// Fungsi atomic fetch & mark
func fetchAndMarkNextPendingHost(db *sql.DB) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var ipBytes []byte
	var id int
	// Ambil id terkecil yang status pending
	err = tx.QueryRow(`SELECT id, ip FROM hosts WHERE status = 'pending' ORDER BY id ASC LIMIT 1 FOR UPDATE`).Scan(&id, &ipBytes)
	if err != nil {
		return "", err // no rows = selesai
	}

	_, err = tx.Exec(`UPDATE hosts SET status = 'scanning' WHERE id = ?`, id)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return net.IP(ipBytes).String(), nil
}

func fetchAndMarkNextPendingHosts(db *sql.DB, batchSize int) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, ip FROM hosts WHERE status = 'pending' ORDER BY id ASC LIMIT ? FOR UPDATE`, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int
	var ips []string
	for rows.Next() {
		var id int
		var ipBytes []byte
		if err := rows.Scan(&id, &ipBytes); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		ips = append(ips, net.IP(ipBytes).String())
	}
	if len(ids) == 0 {
		return nil, sql.ErrNoRows
	}

	// Update status untuk batch
	query := "UPDATE hosts SET status = 'scanning' WHERE id IN (?" + strings.Repeat(",?", len(ids)-1) + ")"
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	_, err = tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ips, nil
}
