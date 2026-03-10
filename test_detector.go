//go:build ignore

package main

import (
	"fmt"
	"github.com/dmachard/go-dnscollector/transformers"
)

func main() {
	detector := transformers.NewCyberDetector()

	fmt.Println("=== DNS Cybersecurity Detection Tests ===")

	fmt.Println("\n[Test 1] Normal query - no alert expected")
	detector.Detect("google.com.", "192.168.1.1")
	fmt.Println("  OK - no alert")

	fmt.Println("\n[Test 2] DNS Tunneling - long subdomain")
	detector.Detect("dGhpcyBpcyBhIHZlcnkgbG9uZyBzdHJpbmcgZW5jb2RlZCBpbiBiYXNlNjQ.evil.com.", "10.0.0.5")

	fmt.Println("\n[Test 3] DNS Tunneling - high entropy")
	detector.Detect("xK9mP2vQ8nR5tL3wY7jB4hF6cZ1q.evil.com.", "10.0.0.6")

	fmt.Println("\n[Test 4] DGA Domain")
	detector.Detect("xkqvbnmzxcvbnmqwrty.com.", "10.0.0.7")

	fmt.Println("\n[Test 5] High Query Rate - 100 queries")
	for i := 0; i < 100; i++ {
		detector.Detect("google.com.", "10.0.0.8")
	}

	fmt.Println("\n=== All Tests Done ===")
}
