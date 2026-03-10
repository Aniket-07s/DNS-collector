package transformers

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

type queryTracker struct {
	mu     sync.Mutex
	counts map[string]int
	window time.Time
}

func newQueryTracker() *queryTracker {
	return &queryTracker{
		counts: make(map[string]int),
		window: time.Now(),
	}
}

func (qt *queryTracker) record(ip string) int {
	qt.mu.Lock()
	defer qt.mu.Unlock()
	if time.Since(qt.window) > 60*time.Second {
		qt.counts = make(map[string]int)
		qt.window = time.Now()
	}
	qt.counts[ip]++
	return qt.counts[ip]
}

func calcEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len(s))
	var e float64
	for _, count := range freq {
		p := count / length
		e -= p * math.Log2(p)
	}
	return e
}

type CyberDetector struct {
	tracker *queryTracker
}

func NewCyberDetector() *CyberDetector {
	return &CyberDetector{
		tracker: newQueryTracker(),
	}
}

func (cd *CyberDetector) Detect(qname string, srcIP string) {
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")

	// Detection 1: DNS Tunneling
	for _, part := range parts {
		if len(part) > 50 {
			fmt.Printf("\n[ALERT] DNS TUNNELING - Long subdomain (%d chars): %s | From: %s\n",
				len(part), qname, srcIP)
		}
		if len(part) > 10 && calcEntropy(part) > 2.5 {
			fmt.Printf("\n[ALERT] DNS TUNNELING - High entropy (%.2f): %s | From: %s\n",
				calcEntropy(part), qname, srcIP)
		}
	}

	// Detection 2: High Query Rate
	count := cd.tracker.record(srcIP)
	if count > 0 && count%100 == 0 {
		fmt.Printf("\n[ALERT] HIGH QUERY RATE - IP %s made %d queries in 60s!\n",
			srcIP, count)
	}

	// Detection 3: DGA Domain
	if len(parts) > 0 {
		domain := parts[0]
		if len(domain) > 12 && calcEntropy(domain) > 2.8 {
			consonants := "bcdfghjklmnpqrstvwxyz"
			consonantCount := 0
			for _, c := range strings.ToLower(domain) {
				if strings.ContainsRune(consonants, c) {
					consonantCount++
				}
			}
			ratio := float64(consonantCount) / float64(len(domain))
			if ratio > 0.6 {
				fmt.Printf("\n[ALERT] DGA DOMAIN - Malware-generated domain: %s | From: %s\n",
					qname, srcIP)
			}
		}
	}
}
