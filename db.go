package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
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
	createTable := `CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		host TEXT,
		port INTEGER,
		vector TEXT,
		hitrate TEXT,
		ampfactor TEXT,
		latency TEXT
	);`
	_, err := db.Exec(createTable)
	return err
}

func insertResult(db *sql.DB, result ScanResult) error {
	_, err := db.Exec(`INSERT INTO scan_results (host, port, vector, hitrate, ampfactor, latency) VALUES (?, ?, ?, ?, ?, ?)`,
		result.Host, result.Port, result.Name, result.HitRate, result.AmpFactor, result.Latency)
	return err
}

// Tambahkan fungsi untuk inisialisasi tabel hosts dan batch insert
func initHostsTable(db *sql.DB) error {
	createTable := `CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		ip TEXT UNIQUE,
		status TEXT DEFAULT 'pending'
	);`
	_, err := db.Exec(createTable)
	return err
}

func insertHostsFromFile(db *sql.DB, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT IGNORE INTO hosts (ip) VALUES (?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		if strings.HasSuffix(ip, "/24") {
			base := strings.TrimSuffix(ip, "/24")
			parts := strings.Split(base, ".")
			if len(parts) != 4 {
				continue
			}
			baseIP := strings.Join(parts[:3], ".")
			for i := 0; i < 256; i++ {
				fullIP := fmt.Sprintf("%s.%d", baseIP, i)
				if net.ParseIP(fullIP) == nil {
					continue
				}
				_, err := stmt.Exec(fullIP)
				if err != nil {
					return err
				}
			}
		} else {
			if net.ParseIP(ip) == nil {
				continue
			}
			_, err := stmt.Exec(ip)
			if err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func updateHostStatus(db *sql.DB, ip, status string) error {
	_, err := db.Exec(`UPDATE hosts SET status = ? WHERE ip = ?`, status, ip)
	return err
}

// Fungsi atomic fetch & mark
func fetchAndMarkNextPendingHost(db *sql.DB) (string, error) {
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var ip string
	err = tx.QueryRow(`SELECT ip FROM hosts WHERE status = 'pending' LIMIT 1 FOR UPDATE`).Scan(&ip)
	if err != nil {
		return "", err // no rows = selesai
	}

	_, err = tx.Exec(`UPDATE hosts SET status = 'scanning' WHERE ip = ?`, ip)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return ip, nil
}
