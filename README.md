Here is the README with proper GitHub Markdown tables:

```markdown
# MCP Injection Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)](https://github.com/yourname/mcp-inject)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**A high-performance, multi-threaded MCP (Model Context Protocol) injection scanner with 2,338 payloads, 70+ wordlists, evasion techniques, and auto-exploitation capabilities.**

---

## Table of Contents

- [What is MCP?](#what-is-mcp)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Line Options](#command-line-options)
- [Examples](#examples)
- [Understanding Results](#understanding-results)
- [Evasion Mode](#evasion-mode)
- [Exploit Mode](#exploit-mode)
- [Report Formats](#report-formats)
- [Building a Test Server](#building-a-test-server)
- [Architecture](#architecture)
- [Wordlists](#wordlists)
- [Contributing](#contributing)
- [License](#license)

---

## What is MCP?

**MCP (Model Context Protocol)** is a protocol that allows AI assistants (like Claude, Cursor, and others) to communicate with external tools, servers, and data sources. It enables AI to execute commands, read files, fetch URLs, and interact with infrastructure.

**The Problem:** Many MCP servers are implemented with insufficient input validation, leading to injection vulnerabilities. This scanner finds them before attackers do.

---

## Features

| Category | Features |
|----------|----------|
| Payloads | 2,338 total (68 base payloads expanded with 70+ wordlists) |
| Injection Categories | Command injection, SQL injection, Path Traversal, SSTI, SSRF, XXE, NoSQL, LDAP, EL Injection, Log Injection, SSI, Prototype Pollution, Header Injection, ReDoS |
| Performance | Multi-threaded (1-32 threads), configurable rate limiting |
| Evasion | Case variation, whitespace obfuscation, encoding, comment insertion |
| Exploitation | Automatic RCE, file read, SSRF tunneling, reverse shells |
| Transports | HTTP, WebSocket, STDIO, SSE |
| Reporting | JSON, human-readable text, and HTML reports |
| Proxy Support | Burp Suite and OWASP ZAP compatible |

---

## Installation

### Dependencies

```bash
# Ubuntu / Debian / Kali
sudo apt update
sudo apt install -y libcurl4-openssl-dev libjson-c-dev libssl-dev gcc make

# Optional - WebSocket support
sudo apt install -y libwebsockets-dev
```

### Build from Source

```bash
git clone https://github.com/yourname/mcp-inject.git
cd mcp-inject
make
sudo make install
```

### Verify Installation

```bash
mcp-inject -h
```

---

## Quick Start

```bash
# Basic scan
./mcp-inject -t http://localhost:8080

# Verbose scan
./mcp-inject -t http://localhost:8080 -v

# Full power (evasion + exploit)
./mcp-inject -t http://localhost:8080 -v -e -E -T 8

# Save report
./mcp-inject -t http://localhost:8080 -o scan_report.json
```

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target URL` | Target MCP server URL | Required |
| `-T, --threads NUM` | Number of concurrent threads | 4 |
| `-r, --rate-limit MS` | Delay between requests in milliseconds | 0 |
| `--timeout SEC` | Request timeout in seconds | 15 |
| `-x, --proxy URL` | Proxy URL (e.g., http://127.0.0.1:8080) | None |
| `-A, --user-agent UA` | Custom User-Agent string | MCP-Inject-Scanner/2.0 |
| `--transport TYPE` | Transport protocol: http, websocket, stdio, sse | http |
| `-e, --exploit` | Enable auto-exploitation mode | Off |
| `-E, --evasion` | Enable WAF evasion mode | Off |
| `-v, --verbose` | Enable verbose output | Off |
| `-q, --quiet` | Suppress all output except findings | Off |
| `--log-file FILE` | Write logs to file | None |
| `--log-level LEVEL` | Log level: debug, info, warn, error | info |
| `-o, --output FILE` | Output report file | report_<timestamp>.json |
| `-h, --help` | Show help message | - |

---

## Examples

```bash
# Basic scan against local server
./mcp-inject -t http://localhost:8080 -v

# Scan with 16 threads and rate limiting
./mcp-inject -t http://target.com -T 16 -r 100

# Scan through Burp Suite proxy
./mcp-inject -t http://target.com -x http://127.0.0.1:8080 -v

# WebSocket target
./mcp-inject -t ws://target.com:8080 --transport websocket -v

# Full aggressive scan
./mcp-inject -t http://target.com -v -e -E -T 32 -r 0 -o full_scan.json

# Scan with custom User-Agent
./mcp-inject -t http://target.com -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Quiet scan (only show vulnerabilities)
./mcp-inject -t http://target.com -q -o report.json
```

---

## Understanding Results

### Vulnerability Output

```
2026-06-09 17:31:48 [VULN] [CRITICAL] CMD-001-V2 - Command Injection - Basic $(whoami)
```

| Field | Description |
|-------|-------------|
| 2026-06-09 17:31:48 | Timestamp of detection |
| [VULN] | Detection type (vulnerability found) |
| [CRITICAL] | Severity level |
| CMD-001-V2 | Payload ID |
| Command Injection - Basic $(whoami) | Payload name and description |

### Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| CRITICAL | Remote code execution possible | Command injection, SSTI |
| HIGH | Data breach or system compromise | SQL injection, Path traversal, SSRF |
| MEDIUM | Information disclosure | XXE, NoSQL injection |
| LOW | Minor issues | Log injection |
| INFO | Informational only | Version disclosure |

---

## Evasion Mode

Evasion mode (`-E`) applies multiple obfuscation techniques to bypass WAFs and input filters.

### Techniques Used

| Technique | Description | Example |
|-----------|-------------|---------|
| Case Variation | Randomly changes letter case | SeLeCt instead of SELECT |
| Whitespace Obfuscation | Replaces spaces with variants | %20, %09, +, /**/ |
| Encoding | URL, double URL, base64, hex | %27%20OR%20%271%27%3D%271 |
| Comment Insertion | Injects SQL comments | SEL/*comment*/ECT |

### Example

Without evasion:
```
$(whoami)
```

With evasion:
```
%24%28%77%68%6f%61%6d%69%29
```

---

## Exploit Mode

Exploit mode (`-e`) automatically attempts to exploit found vulnerabilities.

### Capabilities

| Vulnerability | Exploitation Action |
|---------------|---------------------|
| Command Injection | Execute id, whoami, uname -a |
| Path Traversal | Read /etc/passwd, /etc/hosts |
| SSRF | Fetch cloud metadata, scan internal ports |
| SQL Injection | Extract database names, tables |
| Template Injection | Attempt RCE via template engine |

### Example Output

```
2026-06-09 17:31:48 [VULN] [CRITICAL] CMD-001 - Command Injection
2026-06-09 17:31:48 [INFO] Auto-exploit successful on CMD-001
2026-06-09 17:31:48 [INFO] Command output: uid=33(www-data) gid=33(www-data)
```

---

## Report Formats

### JSON Report

```json
{
  "metadata": {
    "tool": "MCP-Inject-Scanner",
    "version": "2.0.0",
    "timestamp": "2026-06-09T17:31:48+0000",
    "target": "http://localhost:8080"
  },
  "summary": {
    "total_payloads": 2338,
    "vulnerabilities_found": 47,
    "scan_duration_seconds": 12.45,
    "severity_breakdown": {
      "critical": 31,
      "high": 16,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "id": "CMD-001-V2",
      "name": "Command Injection - Basic",
      "category": "command_injection",
      "severity": "CRITICAL",
      "evidence": "Found 'uid=' in response",
      "response_time_ms": 45.2
    }
  ]
}
```

### Text Report

```
============================================================
MCP INJECTION SCAN REPORT
============================================================

Target: http://localhost:8080
Scan Time: 2026-06-09 17:31:48

============================================================
SCAN SUMMARY
============================================================
Total Payloads Tested:    2338
Vulnerabilities Found:    47
Scan Duration:            12.45 seconds

Severity Breakdown:
  [CRITICAL]  31
  [HIGH]      16
  [MEDIUM]    0
  [LOW]       0
  [INFO]      0

============================================================
VULNERABILITIES FOUND
============================================================

[1] Command Injection - Basic (CMD-001-V2)
    Category:   command_injection
    Severity:   CRITICAL
    Evidence:   Found 'uid=' in response
    Response:   45.20 ms, 1243 bytes
```

### HTML Report

Open `web/index.html` in a browser and load the JSON report for an interactive dashboard.

---

## Building a Test Server

### Vulnerable Go MCP Server

Create a file `server.go`:

```go
package main

import (
    "encoding/json"
    "net/http"
    "os/exec"
)

func main() {
    http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
        var req map[string]interface{}
        json.NewDecoder(r.Body).Decode(&req)
        
        cmd := req["params"].(map[string]interface{})["arguments"].(map[string]interface{})["command"].(string)
        output, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
        
        json.NewEncoder(w).Encode(map[string]interface{}{
            "jsonrpc": "2.0",
            "result":  map[string]string{"output": string(output)},
        })
    })
    http.ListenAndServe(":8080", nil)
}
```

Run it:

```bash
go run server.go
```

Then scan:

```bash
./mcp-inject -t http://localhost:8080 -v
```

---

## Architecture

```
mcp-inject/
├── include/
│   └── mcp-inject.h          # Main header
├── src/
│   ├── main.c                # Entry point
│   ├── core/
│   │   ├── scanner.c         # Orchestration
│   │   ├── transport.c       # Network layer
│   │   ├── payload.c         # Payload loading
│   │   ├── detect.c          # Vulnerability detection
│   │   ├── exploit.c         # Auto-exploitation
│   │   ├── report.c          # Report generation
│   │   └── evasion.c         # WAF evasion
│   └── utils/
│       ├── crypto.c          # Encoding utilities
│       └── logger.c          # Logging
├── config/
│   ├── payloads.json         # Base payloads
│   ├── signatures.json       # Detection signatures
│   └── wordlists/            # 70+ wordlist files
├── web/
│   ├── index.html            # Report viewer
│   └── style.css             # Viewer styles
└── reports/                  # Generated reports
```

---

## Wordlists

The scanner includes 70+ wordlist files across multiple categories:

| Category | Files | Purpose |
|----------|-------|---------|
| command_injection | 7 | Unix commands, reverse shells, time-based |
| path_traversal | 5 | Linux/Windows paths, bypass patterns |
| sql_injection | 9 | MySQL, PostgreSQL, MSSQL, blind vectors |
| template_injection | 6 | Jinja2, Twig, Freemarker, Velocity |
| ssrf | 6 | Cloud metadata, internal services |
| xxe | 5 | File read, SSRF, blind XXE |
| nosql_injection | 3 | MongoDB, CouchDB vectors |
| ldap_injection | 2 | Bypass vectors, info leak |
| log_injection | 2 | CRLF, log shipping |
| evasion | 6 | WAF bypass, case variations, polyglots |
| user_agents | 4 | Browsers, bots, mobile, IoT |
| discovery | 5 | Endpoints, MCP paths, backups |
| exploitation | 6 | File write, cron jobs, SSH keys, webshells |
| fuzzing | 5 | Parameters, headers, methods, encodings |

**Total:** 71 wordlist files, approximately 1,500+ entries.

---

### Guidelines

- Follow existing code style
- Add tests for new functionality
- Update documentation
- Keep wordlists up to date

---

## License

MIT License

Copyright (c) 2026 MCP Injection Scanner Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Acknowledgments

- OWASP for injection attack references
- ENISA for threat intelligence
- The MCP community for protocol documentation
- All contributors and testers
