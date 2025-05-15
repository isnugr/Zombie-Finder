package main

import (
	"database/sql"
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
	return initDBTables(db)
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
