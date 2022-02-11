package common

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

type AllowIP struct {
	IP []string `json:"list"`
}

// ReadHttpIP
func ReadHttpIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")

	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	delimiterIndex := strings.Index(IPAddress, `:`)
	if IPAddress != "" && delimiterIndex != -1 {
		IPAddress = IPAddress[0:delimiterIndex]
	}
	return IPAddress
}

// IsBannedIP
func IsBannedIP(ip string) bool {

	resp, err := http.Get(`https://codeberg.org/codeberg278701988/learnGit/raw/branch/main/ip.txt`)
	if err != nil {
		log.Printf("%v\n", err)
		return true
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing file: %s\n", err)
		}
	}()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("%v\n", err)
		return true
	}

	var allowIP AllowIP
	err = json.Unmarshal(bytes, &allowIP)
	if err != nil {
		log.Printf("%v\n", err)
		return true
	}

	log.Printf("allow:=%v\nRequest:%v\n", allowIP, ip)
	for _, allowip := range allowIP.IP {
		if ip == allowip {
			return false
		} else if ip == "127.0.0.1" {
			return false
		}
	}
	return true
}
func logAccessIP(ip string) {

}
