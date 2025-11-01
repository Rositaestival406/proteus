# PROTEUS

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.83+-orange.svg" alt="Rust" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
  <img src="https://img.shields.io/badge/Status-Beta-yellow.svg" alt="Status" />
  <img src="https://img.shields.io/github/stars/ChronoCoders/proteus?style=social" alt="Stars" />
  <img src="https://img.shields.io/github/forks/ChronoCoders/proteus?style=social" alt="Forks" />
  <img src="https://img.shields.io/github/issues/ChronoCoders/proteus" alt="Issues" />
  <img src="https://img.shields.io/github/release/ChronoCoders/proteus" alt="Release" />
</p>

<p align="center">
  <strong>Advanced zero-day static analysis engine built with Rust and Python</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="https://github.com/ChronoCoders/proteus/wiki">Documentation</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

**Advanced Zero-Day Static Analysis Engine**

Proteus is a high-performance malware analysis tool built with Rust and Python, designed to detect zero-day threats through static analysis, heuristics, and machine learning.

## 🎯 Features

### Core Analysis
- 🔍 **PE/ELF Binary Analysis** - Deep inspection of Windows and Linux executables
- 📊 **Entropy Calculation** - Detect packed/encrypted malware (section-level granularity)
- 🧠 **Heuristic Scoring** - Intelligent threat assessment with configurable thresholds
- 🔤 **String Extraction** - ASCII and wide string analysis with pattern detection
- 🌐 **IOC Detection** - Automatic extraction of URLs, IPs, registry keys, file paths
- ⚡ **High Performance** - Rust-powered core with parallel processing via Rayon
- 📦 **Batch Processing** - Scan entire directories efficiently

### Advanced Features
- 🤖 **ML Ready** - Feature extraction pipeline for machine learning
- 📈 **Feature Engineering** - 16+ features including entropy, imports, exports, strings
- 🎯 **Detection Metrics** - Built-in accuracy, precision, recall tracking
- 🔧 **Extensible** - Modular architecture for custom analyzers
- 🔒 **Security Hardened** - Path traversal protection, input validation, rate limiting
- ⚙️ **Configuration Management** - Environment variables, config files, secure storage

## 📊 Detection Metrics (Test Dataset)

| Metric | Value |
|--------|-------|
| Detection Rate | 100% |
| False Positive Rate | 0% |
| Avg Clean Score | 20.73/100 |
| Avg Malicious Score | 66.00/100 |

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.83+ ([Install](https://rustup.rs/))
- **Python** 3.10+ ([Install](https://www.python.org/downloads/))
- **Windows** 10/11 or **Linux**
- **YARA** 4.5+ (Optional, required for Rust build - [Install Guide](install_yara_windows.ps1))
- **MalwareBazaar API Key** (Free - [Get one here](https://bazaar.abuse.ch/account/))

### Installation
```bash
# Clone repository
git clone https://github.com/ChronoCoders/proteus.git
cd proteus

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install Python dependencies
pip install -r requirements.txt

# Build Rust module
maturin develop --release
```

### Configuration

**Option 1: Using .env file (Recommended)**
```bash
# Create .env file in project root
echo "MALWAREBAZAAR_API_KEY=your_api_key_here" > .env
```

**Option 2: Using environment variables**
```bash
# Windows
set MALWAREBAZAAR_API_KEY=your_api_key_here

# Linux/Mac
export MALWAREBAZAAR_API_KEY=your_api_key_here
```

**Option 3: Using config file**
```bash
# Config is automatically saved to ~/.proteus/config.json
# after first run or manual configuration
```

### Basic Usage

**Analyze a single file:**
```bash
python cli.py file C:\path\to\sample.exe
```

**Analyze with full string extraction:**
```bash
python cli.py file C:\path\to\sample.exe --strings
```

**String-only analysis:**
```bash
python cli.py strings C:\path\to\sample.exe
```

**Batch scan directory:**
```bash
python cli.py dir C:\path\to\samples --output results.json
```

### Collecting Real Malware Dataset

**Collect malware samples from MalwareBazaar:**
```bash
# Default: 50 samples per tag (~500 total)
python malware_collector.py

# Custom sample count
python malware_collector.py --samples=100  # ~1000 total

# With verbose output
python malware_collector.py --verbose
```

**Features:**
- ✅ Automatic AES-encrypted ZIP extraction via pyzipper
- ✅ SHA256 hash verification of extracted content
- ✅ Retry logic for failed downloads
- ✅ Real-time progress tracking
- ✅ Graceful interrupt handling (Ctrl+C saves progress)
- ✅ Metadata persistence for resume capability
- ✅ 10 malware categories: ransomware, trojan, rat, stealer, backdoor, loader, miner, banker, spyware, worm

**Collection Statistics:**
- Default: ~500 samples in ~17 minutes
- Large: ~1000 samples in ~33 minutes
- Custom: configurable via `--samples=N`

### Building Test Dataset
```bash
python test_dataset_builder.py
```

### Training ML Models
```bash
python ml_trainer.py
```

## 📖 Documentation

### Example Output
```
╔═══════════════════════════════════════╗
║         PROTEUS v0.1.3                ║
║   Zero-Day Static Analysis Engine     ║
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

[*] String Analysis:
[+] Total strings: 342
[+] Encoded strings: 15

[!] URLs (2):
    http://malicious-c2.com/payload
    https://evil.net/download

[!] Suspicious strings (8):
    cmd.exe /c powershell
    Disable-WindowsDefender
    keylogger.dll
```

### Architecture
```
proteus/
├── src/                      # Rust core engine
│   ├── lib.rs                # Module entry point
│   ├── pe_parser.rs          # PE file parsing (goblin)
│   ├── elf_parser.rs         # ELF file parsing
│   ├── entropy.rs            # Shannon entropy calculation
│   ├── heuristics.rs         # Threat scoring algorithms
│   ├── string_extractor.rs   # String analysis engine
│   └── python_bindings.rs    # PyO3 FFI bindings
├── python/                   # Python orchestration
│   ├── __init__.py
│   ├── analyzer.py           # Main analyzer class
│   ├── ml_detector.py        # ML model integration
│   ├── config.py             # Configuration management
│   ├── validators.py         # Security validators
│   └── rate_limiter.py       # API rate limiting
├── cli.py                    # Command-line interface
├── malware_collector.py      # MalwareBazaar dataset collector
├── ml_trainer.py             # ML training pipeline
├── test_dataset_builder.py   # Dataset generation
├── requirements.txt          # Python dependencies
├── Cargo.toml                # Rust dependencies
├── .env.example              # Example environment config
└── pyproject.toml            # Python project configuration
```

### New in v0.1.3

**Configuration Management:**
```python
from python.config import ConfigManager, ProteusConfig

# Load configuration
config = ConfigManager.create_proteus_config()

# Access settings
print(f"API Key: {config.api_key}")
print(f"Rate Limit: {config.rate_limit_requests} req/{config.rate_limit_window}s")
```

**Rate Limiting:**
```python
from python.rate_limiter import RateLimiter

# Create rate limiter: 10 requests per 60 seconds
limiter = RateLimiter(max_requests=10, time_window=60.0)

# Wait if needed before making request
if limiter.wait_if_needed(timeout=30):
    # Make API request
    pass
```

**Security Validation:**
```python
from python.validators import SecurityValidator

# Validate file path
safe_path = SecurityValidator.validate_file_path("/path/to/file.exe")

# Validate SHA256 hash
is_valid = SecurityValidator.validate_sha256("abc123...")

# Sanitize filename
clean_name = SecurityValidator.sanitize_filename("evil<>file.exe")
```

### Feature Extraction

Proteus extracts 16+ features per sample:

**Binary Features:**
- Global entropy
- Section count
- Max section entropy
- Import count
- Export count
- Suspicious API count

**String Features:**
- Total strings
- URL count
- IP count
- Registry key count
- Suspicious keyword count
- File path count
- Encoded string count
- Encoded ratio
- Suspicious ratio

### Threat Detection Patterns

**High Entropy Indicators:**
- Entropy > 7.8: Likely packed/encrypted
- Entropy > 7.5: Suspicious compression
- Entropy > 7.2: Elevated entropy

**Suspicious APIs (PE):**
```
VirtualAlloc, VirtualProtect, WriteProcessMemory,
CreateRemoteThread, LoadLibrary, GetProcAddress,
WinExec, ShellExecute, URLDownloadToFile,
CreateProcess, OpenProcess, ReadProcessMemory,
SetWindowsHookEx, GetAsyncKeyState, InternetOpen
```

**Suspicious Symbols (ELF):**
```
execve, system, fork, ptrace, mprotect,
mmap, dlopen, socket, bind
```

**Suspicious Keywords (Strings):**
```
cmd, powershell, eval, exec, system, shell,
download, upload, exploit, payload, inject,
keylog, screenshot, webcam, ransomware,
encrypt, bitcoin, miner, bypass, disable
```

## 🔬 Development

### Build & Test
```bash
# Development build
maturin develop

# Release build
maturin develop --release

# Run Rust tests
cargo test

# Run Python tests
python -m pytest

# Type checking
cargo clippy
mypy .
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- **Rust:** Follow `rustfmt` and `clippy` recommendations
- **Python:** Follow PEP 8, type hints required
- **No comments in code** (self-documenting code preferred)
- Use latest stable versions of dependencies

## 🗺️ Roadmap

### v0.1.3 (Current) ✅
- [x] Configuration management system
- [x] API rate limiting
- [x] Security validators
- [x] Environment variable support
- [x] Fixed API authentication
- [x] Removed hardcoded credentials

### v0.2.0 (Planned)
- [ ] YARA rule engine integration
- [ ] Advanced packer detection (UPX, ASPack, Themida)
- [ ] Digital signature validation
- [ ] PE resource section analysis
- [ ] Retrain ML models with real-world dataset (500+ samples)
- [ ] Web UI dashboard

### v0.3.0 (Future)
- [ ] HTML report generation
- [ ] REST API server
- [ ] Real-time monitoring
- [ ] PCAP analysis integration
- [ ] Behavior monitoring (dynamic analysis)
- [ ] Distributed scanning

## 📊 Performance

**Benchmarks (Intel i7, 16GB RAM):**
- Single file analysis: ~50ms
- Batch processing (100 files): ~3 seconds
- String extraction: ~20ms
- ML prediction: ~5ms
- Malware collection: ~200 samples in ~6 minutes

## ⚠️ Limitations

**Current Version (v0.1.3):**
- ML models require training on collected real-world samples
- No dynamic analysis capabilities
- Windows-focused (PE analysis more mature than ELF)
- Dataset collection requires MalwareBazaar API access
- Rate limiting may slow down large collections

**Recommended Use:**
- Educational purposes
- Research projects
- Malware analysis training
- Static analysis component in larger systems
- Dataset collection for ML training

## 🔒 Security & Legal

**Important Notes:**
- Always analyze malware in isolated environments (VMs/sandboxes)
- Do not use on production systems without proper testing
- Obey local laws regarding malware possession and analysis
- This tool is for educational and research purposes only
- Never hardcode API keys in source code

**Disclaimer:**
The authors are not responsible for misuse of this tool. Users are solely responsible for ensuring their usage complies with applicable laws and regulations.

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

Copyright (c) 2025 ChronoCoders

## 👥 Authors

**ChronoCoders Team**
- Advanced static analysis engine
- ML integration
- Performance optimization
- Security hardening

## 🙏 Acknowledgments

- **goblin** - Excellent binary parsing library
- **PyO3** - Seamless Rust-Python integration
- **Rayon** - Parallel processing made easy
- **scikit-learn** - ML algorithms
- **pyzipper** - AES-encrypted ZIP extraction
- **MalwareBazaar** - Real-world malware sample repository
- **python-dotenv** - Environment configuration management

---

## 📚 Additional Resources

- [Documentation](https://github.com/ChronoCoders/proteus/wiki)
- [API Reference](https://github.com/ChronoCoders/proteus/wiki/API)
- [Examples](https://github.com/ChronoCoders/proteus/tree/main/examples)
- [Contributing Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

---

⭐ **If you find Proteus useful, please star the repository!**

🐛 **Found a bug?** [Open an issue](https://github.com/ChronoCoders/proteus/issues)

💡 **Have a feature request?** [Start a discussion](https://github.com/ChronoCoders/proteus/discussions)