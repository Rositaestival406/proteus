# PROTEUS

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.83+-orange.svg" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
</p>

**Advanced Zero-Day Static Analysis Engine**

Proteus is a high-performance malware analysis tool built with Rust and Python, designed to detect zero-day threats through static analysis, heuristics, and machine learning.

## Features

- 🔍 **PE/ELF Binary Analysis** - Deep inspection of Windows and Linux executables
- 📊 **Entropy Calculation** - Detect packed/encrypted malware
- 🧠 **Heuristic Scoring** - Intelligent threat assessment
- 🔤 **String Extraction** - ASCII and wide string analysis with pattern detection
- 🌐 **IOC Detection** - URLs, IPs, registry keys, file paths
- ⚡ **High Performance** - Rust-powered core with parallel processing
- 🤖 **ML Ready** - Built-in anomaly detection capabilities
- 📦 **Batch Processing** - Scan entire directories efficiently

## Quick Start

### Prerequisites

- Rust 1.83+
- Python 3.10+
- Windows 10/11 or Linux

### Installation
```bash
git clone https://github.com/ChronoCoders/proteus.git
cd proteus
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install maturin
maturin develop --release
```

### Usage

**Analyze a single file:**
```bash
python cli.py file C:\path\to\file.exe
```

**Analyze with string extraction:**
```bash
python cli.py file C:\path\to\file.exe --strings
```

**String-only analysis:**
```bash
python cli.py strings C:\path\to\file.exe
```

**Batch scan directory:**
```bash
python cli.py dir C:\path\to\samples --output results.json
```

## Example Output
```
╔═══════════════════════════════════════╗
║         PROTEUS v0.1.0                ║
║   Zero-Day Static Analysis Engine    ║
╚═══════════════════════════════════════╝

[*] Analysis: suspicious.exe
[+] Type: PE
[+] Entropy: 7.85
[+] Threat Score: 66.00/100
[+] Verdict: MALICIOUS
[!] Suspicious Indicators:
    - VirtualAlloc
    - CreateRemoteThread
    - WriteProcessMemory
```

## Detection Metrics

- **Detection Rate:** 100% on test dataset
- **False Positive Rate:** 0%
- **Average Clean File Score:** 20.73/100
- **Average Malicious Score:** 66.00/100

## Architecture
```
proteus/
├── src/                  # Rust core engine
│   ├── pe_parser.rs      # PE file parsing
│   ├── elf_parser.rs     # ELF file parsing
│   ├── entropy.rs        # Entropy calculation
│   ├── heuristics.rs     # Scoring algorithms
│   └── string_extractor.rs  # String analysis
├── python/               # Python orchestration
│   ├── analyzer.py       # Main analyzer
│   └── ml_detector.py    # ML integration
└── cli.py               # Command-line interface
```

## Threat Detection

Proteus identifies suspicious patterns including:

- High entropy (packed/encrypted executables)
- Dangerous API calls (VirtualAlloc, CreateRemoteThread, etc.)
- Suspicious strings (cmd, powershell, keylog, ransomware, etc.)
- Unusual section counts
- Registry manipulation
- Network indicators (URLs, IPs)

## Development

**Build:**
```bash
maturin develop --release
```

**Run tests:**
```bash
cargo test
python -m pytest
```

**Code quality:**
```bash
cargo clippy
mypy .
```

## Roadmap

- [ ] ML model training pipeline
- [ ] YARA rule engine
- [ ] Advanced packer detection
- [ ] Digital signature validation
- [ ] HTML report generation
- [ ] PCAP analysis
- [ ] Behavior monitoring

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for educational and research purposes only. Always analyze malware in isolated environments.

## Authors

ChronoCoders Team

---

⭐ If you find Proteus useful, please star the repository!
```

## **3. LICENSE dosyası (Root'ta):**
```
MIT License

Copyright (c) 2025 ChronoCoders

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