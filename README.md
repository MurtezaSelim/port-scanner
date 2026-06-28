# 🔍 Port Scanner

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Portfolio](https://img.shields.io/badge/Cybersecurity-Portfolio-green.svg)](https://github.com/MurtezaSelim)

**A professional-grade, multi-threaded TCP port scanner built in pure Python with banner grabbing, service identification, progress tracking, and flexible export options.**

Perfect for cybersecurity portfolios, ethical hacking labs, network reconnaissance practice, and demonstrating practical security assessment skills.

> ⚠️ **For educational and authorized use only.** Never scan networks or systems without explicit permission.

## 🚀 Features

- **High Performance**: Multi-threaded scanning using `concurrent.futures` for speed
- **Banner Grabbing**: Attempts to retrieve service banners from open ports
- **Service Detection**: Maps common ports to service names (SSH, HTTP, HTTPS, etc.)
- **Flexible Targeting**: Hostname or IP address support with automatic resolution
- **Customizable Scans**: Specify port ranges, individual ports, or common top ports
- **Beautiful CLI**: Optional [Rich](https://github.com/Textualize/rich) library for colorful tables, progress bars, and professional output
- **Export Options**: Save results to JSON, CSV, or plain text
- **Configurable**: Adjustable threads, timeout, and verbosity
- **Robust Error Handling**: Timeouts, permission errors, and connection issues handled gracefully
- **Well Documented**: Comprehensive README with examples, architecture explanation, and ethical guidelines

## 📁 Project Structure

```
port-scanner/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
└── port_scanner.py          # Main CLI application
```

## 👨‍💻 Installation

```bash
# Clone the repository
git clone https://github.com/MurtezaSelim/port-scanner.git
cd port-scanner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> **Note**: The `rich` library is optional but highly recommended for the best experience. The script falls back to plain text output if not installed.

## 🚀 Usage

```bash
python port_scanner.py --help

# Basic scan of common ports on a target
python port_scanner.py --target example.com

# Scan specific port range with more threads
python port_scanner.py --target 192.168.1.1 --ports 1-1000 --threads 200 --timeout 0.5

# Scan specific ports and export to JSON
python port_scanner.py --target scanme.nmap.org --ports 22,80,443,8080 --output results.json

# Verbose mode with banner grabbing details
python port_scanner.py --target 10.0.0.1 --ports 1-65535 --verbose
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target hostname or IP address (required) | - |
| `--ports` | Ports to scan. Supports ranges (1-1000), lists (22,80,443), or 'common' | common |
| `--threads` | Number of concurrent threads | 100 |
| `--timeout` | Connection timeout in seconds | 1.0 |
| `--output` | Export file (supports .json, .csv, .txt) | None (print only) |
| `--verbose` | Show detailed progress and banners | False |
| `--no-rich` | Force plain text output even if rich is installed | False |

## 📊 Example Output

```
🔍 Scanning target: scanme.nmap.org (45.33.32.156)
🕒 Started at: 2026-06-28 12:30:15

Port   Status    Service      Banner
------ -------- ------------ --------------------------------
22     OPEN      SSH          SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
80     OPEN      HTTP         HTTP/1.1 200 OK\r\nDate: ...
443    OPEN      HTTPS        

🎯 Scan Summary
✔️ Open ports found: 3
⏱️ Duration: 4.82 seconds
```

(When using Rich: Beautiful colored table with progress bar)

## ⚠️ Ethical Use & Legal Disclaimer

**This tool is provided strictly for educational purposes, personal lab environments, and authorized security assessments.**

- Only use on systems you own or have **written permission** to test.
- Unauthorized scanning may violate laws (e.g., CFAA in the US, Computer Misuse Act in UK).
- The author and contributors are not responsible for any misuse.
- Always follow responsible disclosure and local laws.

By using this software, you agree to use it ethically and legally.

## 🔧 Limitations & Future Improvements

**Current Limitations**:
- TCP connect scan only (no SYN scan without raw sockets/privileges)
- Limited banner grabbing (some services don't send banners or require specific probes)
- No UDP scanning
- No OS fingerprinting or advanced service version detection

**Planned Enhancements** (contributions welcome!):
- [ ] UDP port scanning support
- [ ] Integration with Nmap service probes or version detection
- [ ] Export to HTML report with styling
- [ ] Rate limiting and evasion techniques (for authorized red team simulations)
- [ ] IPv6 support
- [ ] Integration with vulnerability databases for open ports
- [ ] Docker support for easy deployment

## 👩‍💻 Contributing

Contributions are welcome! Please open an issue or pull request.
1. Fork the repo
2. Create feature branch
3. Make your changes with tests if applicable
4. Submit PR

## 🎓 Acknowledgments

Inspired by tools like Nmap, Masscan, and common cybersecurity training resources.
Built as part of a professional cybersecurity portfolio.

---

*Created with ❤️ for the cybersecurity community by MurtezaSelim*