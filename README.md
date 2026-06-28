# 🔍 Port Scanner

A multi-threaded port scanner I wrote in Python while learning about network reconnaissance and security tooling.

It scans TCP ports on a target, tries to grab banners from open services, does basic service guessing, and can save results to files. I added a nice terminal interface using Rich for the output.

**For learning and authorized testing only.** Please don't use this on networks or systems without permission.

## What it does

- Scans ports quickly with multiple threads
- Grabs banners (like SSH version or HTTP headers)
- Guesses common services from port numbers
- Lets you pick specific ports, ranges, or common ones
- Exports results as JSON, CSV, or plain text
- Shows progress and colorful tables (if Rich is installed)

## Quick start

```bash
git clone https://github.com/MurtezaSelim/port-scanner.git
cd port-scanner
pip install -r requirements.txt   # optional but nice for output
python port_scanner.py --help
```

Example:
```bash
python port_scanner.py --target scanme.nmap.org --ports common --verbose
```

Check the script itself for more options and how it works. The main code is in `port_scanner.py`.

I built this to practice Python concurrency, socket programming, and understanding what services run on networks. It's part of my cybersecurity learning portfolio.

## Ethical note

Only scan things you own or have explicit written permission to test. Unauthorized scanning can get you in trouble legally. I'm not responsible for misuse.

---

*Built by Murteza Selim as a hands-on learning project | June 2026*