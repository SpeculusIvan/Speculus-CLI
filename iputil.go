package main

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"strings"

	"github.com/point-c/ipcheck"
)

func IsPublicIPv4(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	if ipcheck.IsLoopback(ip) || ipcheck.IsLinkLocal(ip) || ipcheck.IsPrivateNetwork(ip) {
		return false
	}
	return true
}

func readIPs(path string) ([]net.IP, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		ip := net.ParseIP(strings.TrimSpace(scanner.Text()))
		if IsPublicIPv4(ip) {
			ips = append(ips, ip.To4())
		}
	}
	return ips, scanner.Err()
}
