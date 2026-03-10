# DNS-Collector + Cybersecurity Detection

## Project Overview
This project is a fork of [dmachard/dns-collector](https://github.com/dmachard/dns-collector),
a production-grade DNS traffic analysis tool written in Go.

I added a real-time cybersecurity detection engine that automatically identifies
three types of DNS-based attacks on live network traffic.

## What I Added

### 1. DNS Tunneling Detection
- Flags subdomains longer than 50 characters
- Flags subdomains with Shannon entropy above 2.5
- Attackers hide stolen data inside DNS queries as encoded text
- Example attack: `aGVsbG8gdGhpcyBpcyBzdG9sZW4.evil.com`

### 2. High Query Rate Detection (DDoS)
- Tracks number of queries per source IP in a 60 second window
- Alerts when any IP exceeds 100 queries per minute
- Detects DNS amplification and flood attacks
- Uses thread-safe Go map with mutex locking

### 3. DGA Domain Detection
- Detects algorithmically generated domains used by malware botnets
- Uses Shannon entropy scoring above 2.8
- Uses consonant ratio analysis above 0.6
- Real domains have natural vowel/consonant mix, malware domains do not

## Files Added
| File | Description |
|------|-------------|
| `transformers/cyber_detector.go` | Core detection engine with all 3 detectors |
| `workers/dnsprocessor.go` | Hooked detector into live DNS pipeline |
| `test_detector.go` | Unit tests for all detectors |

## How It Works - Architecture
```
Network Traffic
      ↓
[afpacket sniffer] - captures raw DNS packets from eth0
      ↓
[dnsprocessor] - parses DNS payload, extracts Qname and IP
      ↓
[CyberDetector] - MY ADDITION
   ├── DNS Tunneling Check (entropy + subdomain length)
   ├── High Query Rate Check (per-IP rate tracker)
   └── DGA Domain Check (consonant ratio + entropy)
      ↓
[ALERT printed to console in real time]
```

## Test Results
All 5 detection tests passing:

| Test | Expected | Result |
|------|----------|--------|
| Normal query (google.com) | No alert | PASS |
| DNS Tunneling - long subdomain | ALERT | PASS |
| DNS Tunneling - high entropy | ALERT | PASS |
| DGA Domain detection | ALERT | PASS |
| High Query Rate (100 queries) | ALERT | PASS |

## How to Run

### Prerequisites
- Linux or WSL (Ubuntu)
- Go 1.21 or higher
- tcpdump installed

### Build
```bash
go build -o dnscollector .
```

### Run Live Detection
```bash
sudo ./dnscollector -config config.yml
```

### Run Unit Tests
```bash
go run test_detector.go
```

### Simulate Attack (in second terminal)
```bash
# Normal query - no alert
dig google.com @8.8.8.8

# DNS Tunneling attack simulation
dig xK9mP2vQ8nR5tL3wY7jB4hF6cZ1qA2sD3eF4gH5.evil-domain.com @8.8.8.8
```

## Sample Alert Output
```
[ALERT] DNS TUNNELING - High entropy (5.03): xK9mP2vQ8nR5tL3wY7jB4hF6cZ1qA2sD3eF4gH5.evil-domain.com | From: 172.24.189.245
[ALERT] DGA DOMAIN - Malware-generated domain: xK9mP2vQ8nR5tL3wY7jB4hF6cZ1qA2sD3eF4gH5.evil-domain.com | From: 172.24.189.245
[ALERT] HIGH QUERY RATE - IP 10.0.0.8 made 100 queries in 60s!
```

## Technologies Used
- Go (Golang) - systems programming language
- Shannon Entropy - mathematical randomness measurement
- afpacket - Linux raw network packet capture
- DNStap protocol - DNS traffic analysis
- Git / GitHub - version control

## Author
Aniket
GitHub: https://github.com/Aniket-07s/DNS-collector
