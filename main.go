// ampscan.go
// A simple tool for finding open UDP applications vulnerable to amplification and reflection
// Use only for systems you own or have EXPLICIT permission to test.
// Unauthorized portscanning is at best rude and at worst illegal.

package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/schollz/progressbar/v3"
	"github.com/shirou/gopsutil/v3/cpu"
)

// Vector represents a protocol vector that can be used for amplification attacks
type Vector struct {
	Name    string
	Port    int
	Payload []byte
}

// ScanResult represents the result of a scan
type ScanResult struct {
	Host      string
	Port      int
	Name      string
	HitRate   string
	AmpFactor string
	Latency   string
}

// Global variables
var (
	detectTasks  []map[string]interface{}
	measureTasks []map[string]interface{}
	results      []ScanResult
	vectors      = []Vector{
		{
			Name:    "DNS_A",
			Port:    53,
			Payload: []byte{0x61, 0xe4, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x98, 0x66, 0x4e, 0xc7, 0x05, 0x24, 0xbb, 0x9e},
		},
		{
			Name:    "DNS_ANY",
			Port:    53,
			Payload: []byte{0xf1, 0xe8, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x73, 0x6c, 0x00, 0x00, 0xff, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xc0, 0x4e, 0xd3, 0x88, 0xf7, 0x91, 0x6b, 0xb6},
		},
		{
			Name:    "NTP",
			Port:    123,
			Payload: []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00},
		},
		{
			Name:    "cLDAP",
			Port:    389,
			Payload: []byte{0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00},
		},
	}
	mutex = &sync.Mutex{}
)

// Helper functions
func average(values []int) float64 {
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values))
}

func getVector(vectorName string) (Vector, bool) {
	for _, v := range vectors {
		if v.Name == vectorName {
			return v, true
		}
	}
	return Vector{}, false
}

func addDetectTask(host, vectorName string) {
	vector, found := getVector(vectorName)
	if !found {
		return
	}

	task := map[string]interface{}{
		"host":    host,
		"name":    vector.Name,
		"port":    vector.Port,
		"payload": vector.Payload,
	}

	detectTasks = append(detectTasks, task)
}

func addMeasureTask(host, vectorName string) {
	vector, found := getVector(vectorName)
	if !found {
		return
	}

	task := map[string]interface{}{
		"host":    host,
		"name":    vector.Name,
		"port":    vector.Port,
		"payload": vector.Payload,
	}

	mutex.Lock()
	measureTasks = append(measureTasks, task)
	mutex.Unlock()
}

func addResult(result ScanResult) {
	mutex.Lock()
	results = append(results, result)
	mutex.Unlock()
}

func scanHost(task map[string]interface{}, timeout time.Duration, db *sql.DB) bool {
	host := task["host"].(string)
	port := task["port"].(int)

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		updateHostStatus(db, host, "failed")
		return false
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		updateHostStatus(db, host, "failed")
		return false
	}

	err = udpConn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		updateHostStatus(db, host, "failed")
		return false
	}

	response := make([]byte, 1024)
	_, _, err = udpConn.ReadFromUDP(response)
	if err != nil {
		updateHostStatus(db, host, "failed")
		return false
	}

	// If we got a response, add to measure tasks
	addMeasureTask(host, task["name"].(string))
	updateHostStatus(db, host, "done")
	return true
}

func measureHost(task map[string]interface{}, timeout time.Duration) {
	host := task["host"].(string)
	port := task["port"].(int)
	vectorName := task["name"].(string)
	payload := task["payload"].([]byte)

	amount := 50
	failed := 0
	responseSizes := []int{}
	responseLatencies := []int{}

	for i := 0; i < amount; i++ {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			failed++
			continue
		}

		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			failed++
			conn.Close()
			continue
		}

		err = udpConn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			failed++
			conn.Close()
			continue
		}

		start := time.Now()
		_, err = udpConn.Write(payload)
		if err != nil {
			failed++
			conn.Close()
			continue
		}

		response := make([]byte, 1024)
		n, _, err := udpConn.ReadFromUDP(response)
		if err != nil {
			failed++
			conn.Close()
			continue
		}

		elapsed := time.Since(start)
		responseSizes = append(responseSizes, n)
		responseLatencies = append(responseLatencies, int(elapsed.Milliseconds()))
		conn.Close()
	}

	// Calculate results
	hitRate := fmt.Sprintf("%d/%d", failed, amount)

	var ampFactor string
	if len(responseSizes) > 0 {
		factor := average(responseSizes) / float64(len(payload))
		ampFactor = fmt.Sprintf("%.2f", factor)
	} else {
		ampFactor = "0.00"
	}

	var latency string
	if len(responseLatencies) > 0 {
		latency = fmt.Sprintf("%.2f", average(responseLatencies))
	} else {
		latency = "0.00"
	}

	result := ScanResult{
		Host:      host,
		Port:      port,
		Name:      vectorName,
		HitRate:   hitRate,
		AmpFactor: ampFactor,
		Latency:   latency,
	}

	addResult(result)
}

func displayVectors() {
	fmt.Println("Name\t\tPort\tPayload Size")
	fmt.Println("____________________________________")
	for _, v := range vectors {
		fmt.Printf("%s\t\t%d\t%d Bytes\n", v.Name, v.Port, len(v.Payload))
	}
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

// Refactor: initDB hanya buka koneksi, inisialisasi tabel di initAllTables
func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Pindahkan CREATE TABLE scan_results ke fungsi baru
func initDBTables(db *sql.DB) error {
	createTable := `CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
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
		id INTEGER PRIMARY KEY AUTOINCREMENT,
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
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO hosts (ip) VALUES (?)")
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
	err = tx.QueryRow(`SELECT ip FROM hosts WHERE status = 'pending' LIMIT 1`).Scan(&ip)
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

// Tambahkan fungsi untuk mendapatkan load CPU
func getCPUPercent() float64 {
	percents, err := cpu.Percent(0, false)
	if err != nil || len(percents) == 0 {
		return 0
	}
	return percents[0]
}

func main() {
	// Parse command line arguments
	vectorsPtr := flag.String("vectors", "all", "OPTIONAL. Define vectors you want to search for, if left empty then all vectors will be included in the scan. [--vectors display] to list all vectors")
	timeoutPtr := flag.Int("timeout", 250, "OPTIONAL. Define timeout for each UDP packet in ms, 250ms default")
	hostsFilePtr := flag.String("hostsfile", "", "Path to file containing list of hosts, one per line")

	flag.Parse()

	if *vectorsPtr == "display" {
		displayVectors()
		os.Exit(0)
	}

	if *hostsFilePtr == "" {
		fmt.Println("No hosts file provided!")
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutPtr) * time.Millisecond

	// Inisialisasi database
	db, err := initDB("data.db")
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Inisialisasi semua tabel
	if err := initAllTables(db); err != nil {
		fmt.Printf("Failed to initialize tables: %v\n", err)
		os.Exit(1)
	}

	// Masukkan IP dari file ke tabel hosts di database
	if err := insertHostsFromFile(db, *hostsFilePtr); err != nil {
		fmt.Printf("Failed to insert hosts from file: %v\n", err)
		os.Exit(1)
	}

	// Tambahkan tasks deteksi berdasarkan fetchAndMarkNextPendingHost
	for {
		ip, err := fetchAndMarkNextPendingHost(db)
		if err != nil {
			break // tidak ada lagi pending
		}
		for _, vector := range vectors {
			addDetectTask(ip, vector.Name)
		}
	}

	// Detection phase dengan progress bar
	barDetect := progressbar.NewOptions(len(detectTasks),
		progressbar.OptionSetDescription("Detection"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(20),
		progressbar.OptionClearOnFinish(),
	)
	for i := 0; i < len(detectTasks); i++ {
		task := detectTasks[i]
		scanHost(task, timeout, db)
		barDetect.Add(1)
	}

	fmt.Printf("\nFound %d open UDP applications\n", len(measureTasks))

	// Measurement phase dengan progress bar
	iterations := len(measureTasks)
	barMeasure := progressbar.NewOptions(iterations,
		progressbar.OptionSetDescription("Measurement"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(20),
		progressbar.OptionClearOnFinish(),
	)
	var wg sync.WaitGroup
	minWorkers := 2
	maxWorkers := runtime.NumCPU() * 4
	workerCount := runtime.NumCPU()
	measureTaskChan := make(chan map[string]interface{}, iterations)
	for i := 0; i < iterations; i++ {
		measureTaskChan <- measureTasks[i]
	}
	close(measureTaskChan)

	workerQuit := make([]chan struct{}, maxWorkers)
	for i := 0; i < maxWorkers; i++ {
		workerQuit[i] = make(chan struct{})
	}

	activeWorkers := 0
	workerLock := &sync.Mutex{}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Caught interrupt signal, shutting down gracefully...")
		cancel()
	}()

	startWorker := func(idx int) {
		wg.Add(1)
		go func(id int, quit chan struct{}) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-measureTaskChan:
					if !ok {
						return
					}
					measureHost(task, timeout)
					updateHostStatus(db, task["host"].(string), "done")
					barMeasure.Add(1)
				case <-quit:
					return
				}
			}
		}(idx, workerQuit[idx])
	}

	// Start initial workers
	for i := 0; i < workerCount; i++ {
		startWorker(i)
		activeWorkers++
	}

	// Goroutine untuk adaptasi worker
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(5 * time.Second)
				cpuLoad := getCPUPercent()
				workerLock.Lock()
				if cpuLoad > 90 && activeWorkers > minWorkers {
					workerQuit[activeWorkers-1] <- struct{}{}
					activeWorkers--
					fmt.Printf("\n[ADAPT] CPU load %.1f%%, turunkan worker jadi %d\n", cpuLoad, activeWorkers)
				} else if cpuLoad < 70 && activeWorkers < maxWorkers {
					startWorker(activeWorkers)
					activeWorkers++
					fmt.Printf("\n[ADAPT] CPU load %.1f%%, naikkan worker jadi %d\n", cpuLoad, activeWorkers)
				}
				workerLock.Unlock()
				if activeWorkers == 0 {
					return
				}
			}
		}
	}()

	wg.Wait()

	// Print results
	fmt.Println("\n\nHost\tPort\tVector\t\tFailed\tAmp\tLatency")
	fmt.Println("_______________________________________________________")

	for _, result := range results {
		fmt.Printf("%s\t%d\t%s\t\t%s\t%sx\t%sms\n",
			result.Host, result.Port, result.Name, result.HitRate, result.AmpFactor, result.Latency)
		if !strings.HasPrefix(result.HitRate, "50/") { // hanya simpan yang berhasil
			err := insertResult(db, result)
			if err != nil {
				fmt.Printf("Failed to insert result to DB: %v\n", err)
			}
		}
	}
}
