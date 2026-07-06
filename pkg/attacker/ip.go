package attacker

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DetectPublicIP attempts to determine the operator's public IP address.
// Tries checkip.amazonaws.com first, then falls back to local interface detection.
func DetectPublicIP() (string, error) {
	// Try AWS checkip service
	if ip, err := detectViaHTTP(); err == nil {
		return ip, nil
	}

	// Fall back to local interface detection via UDP dial
	if ip, err := detectViaUDP(); err == nil {
		return ip, nil
	}

	return "", fmt.Errorf("could not detect public IP. Use --public-ip to set manually")
}

func detectViaHTTP() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://checkip.amazonaws.com")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP from checkip: %s", ip)
	}
	return ip, nil
}

func detectViaUDP() (string, error) {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
