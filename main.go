// ampscan.go
// A simple tool for finding open UDP applications vulnerable to amplification and reflection
// Use only for systems you own or have EXPLICIT permission to test.
// Unauthorized portscanning is at best rude and at worst illegal.

package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/schollz/progressbar/v3"
)

// Struct untuk vector dan task

type Vector struct {
	Name    string
	Port    int
	Payload []byte
}

type ScanTask struct {
	Host    string
	Name    string
	Port    int
	Payload []byte
}

// Struct untuk hasil scan

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
	// Daftar vector/protokol yang akan discan
	vectors = []Vector{
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
)

// Helper functions
func average(values []int) float64 {
	sum := 0
	for _, v := range values {
		sum += v
	}
	return float64(sum) / float64(len(values))
}

func displayVectors() {
	fmt.Println("Name\t\tPort\tPayload Size")
	fmt.Println("____________________________________")
	for _, v := range vectors {
		fmt.Printf("%s\t\t%d\t%d Bytes\n", v.Name, v.Port, len(v.Payload))
	}
}

func scanAndMeasureHost(task ScanTask, timeout time.Duration, db *sql.DB) bool {
	host := task.Host
	port := task.Port
	vectorName := task.Name
	payload := task.Payload

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return false
	}

	err = udpConn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}

	// Kirim payload untuk scan
	_, err = udpConn.Write(payload)
	if err != nil {
		return false
	}

	response := make([]byte, 1024)
	_, _, err = udpConn.ReadFromUDP(response)
	if err != nil {
		return false
	}

	// Jika dapat respons, lanjutkan measurement
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

	// Hitung hasil
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

	_ = insertResult(db, result)
	return true
}

func readHostsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hosts := []string{}
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
				hosts = append(hosts, ipCopy.String())
			}
		} else {
			hosts = append(hosts, ip)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
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

func main() {
	// Parse command line arguments
	vectorsPtr := flag.String("vectors", "all", "OPTIONAL. Define vectors you want to search for, if left empty then all vectors will be included in the scan. [--vectors display] to list all vectors")
	timeoutPtr := flag.Int("timeout", 250, "OPTIONAL. Define timeout for each UDP packet in ms, 250ms default")
	hostsFilePtr := flag.String("hostsfile", "", "Path to file containing list of hosts, one per line")
	workersPtr := flag.Int("workers", 10, "OPTIONAL. Define number of workers, 10 default")
	dbPtr := flag.String("db", "zombie:123@tcp(127.0.0.1:3306)/zombie", "OPTIONAL. Define database connection string, root:password@tcp(127.0.0.1:3306)/zombiescan default")

	flag.Parse()

	if *vectorsPtr == "display" {
		displayVectors()
		os.Exit(0)
	}

	timeout := time.Duration(*timeoutPtr) * time.Millisecond
	db, err := initDB(*dbPtr)
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Inisialisasi tabel hasil scan
	if err := initAllTables(db); err != nil {
		fmt.Printf("Failed to initialize tables: %v\n", err)
		os.Exit(1)
	}

	if *hostsFilePtr == "" {
		fmt.Println("hostsfile parameter is required!")
		os.Exit(1)
	}

	hosts, err := readHostsFromFile(*hostsFilePtr)
	if err != nil {
		fmt.Printf("Failed to read hosts from file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting scan...")
	var wgDetect sync.WaitGroup
	barProgress := progressbar.NewOptions(len(hosts),
		progressbar.OptionSetDescription("Progress"),
		progressbar.OptionShowCount(),
	)

	taskCh := make(chan string, 100)
	for i := 0; i < *workersPtr; i++ {
		wgDetect.Add(1)
		go func() {
			defer wgDetect.Done()
			for ip := range taskCh {
				for _, vector := range vectors {
					task := ScanTask{
						Host:    ip,
						Name:    vector.Name,
						Port:    vector.Port,
						Payload: vector.Payload,
					}
					_ = scanAndMeasureHost(task, timeout, db)
				}
				barProgress.Add(1)
			}
		}()
	}
	for _, ip := range hosts {
		taskCh <- ip
	}
	close(taskCh)
	wgDetect.Wait()

	// Print statistik dari database
	fmt.Println("\nStatistik hasil scan:")
	var nDetected, nResults int
	row := db.QueryRow("SELECT COUNT(DISTINCT host) FROM scan_results")
	row.Scan(&nDetected)
	row = db.QueryRow("SELECT COUNT(*) FROM scan_results")
	row.Scan(&nResults)
	fmt.Printf("Host terdeteksi open: %d\n", nDetected)
	fmt.Printf("Total hasil (host+vector open): %d\n", nResults)
	fmt.Printf("Total host discan: %d\n", len(hosts))
}
