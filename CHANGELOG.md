# Changelog

All notable changes to Proteus will be documented in this file.

## [0.1.4] - 2025-11-02

### Added
- **ML Prediction Integration**: Random Forest classifier with 96% accuracy
  - Train with 576 real malware samples from MalwareBazaar
  - 614 clean Windows system binaries for balanced training
  - CLI flag `--ml` for ML-powered analysis
  - Confidence scores and probability distributions
  - Isolation Forest for anomaly detection
- **Enhanced ML Training Pipeline**:
  - Automatic error handling for unsupported file types
  - Skip corrupted/malformed binaries gracefully
  - Detailed statistics (processed vs skipped files)
  - Progress tracking during training
  - Support for PE, ELF, and various malware formats

### Changed
- Updated CLI version to v0.1.4
- Improved feature extraction with better error handling
- Enhanced dataset preparation with file type categorization

### Fixed
- Malformed PE/ELF binary handling during training
- UTF-8 encoding errors in string extraction
- Goblin parser errors for anti-analysis malware
- Feature extraction failures logged without crashing

### Performance
- **Detection Metrics**:
  - Test Accuracy: 96.22%
  - Precision (Malicious): 95%
  - Recall (Malicious): 97%
  - F1-Score: 0.96
  - False Positive Rate: 0.97% (6/614)
  - False Negative Rate: 0.52% (3/576)
- **Top Features**: file_paths (23%), section_count (18%), total_strings (13%)

### Technical
- Trained Random Forest with 100 estimators
- 5-fold cross-validation: 94.45% mean accuracy
- Balanced dataset: 576 malware vs 614 clean
- 16 extracted features per sample

## [0.1.3] - 2025-11-01

### Added
- **Configuration Management**: New `config.py` module for centralized configuration
  - Environment variable support (`MALWAREBAZAAR_API_KEY`, `PROTEUS_*`)
  - User config storage in `~/.proteus/config.json`
  - API key persistence and secure storage
- **Rate Limiter**: Thread-safe API rate limiting (`rate_limiter.py`)
  - Configurable requests per time window
  - Prevents API bans from excessive requests
- **Security Validators**: Input validation (`validators.py`)
  - Path traversal protection
  - SHA256 hash validation
  - File size and extension whitelisting
  - Filename sanitization
- **python-dotenv Integration**: Load API keys from `.env` files

### Changed
- **Malware Collector API Auth**: Fixed header from `API-KEY` to `Auth-Key`
- Removed hardcoded API keys from source code
- Improved error messages and exception handling
- Enhanced type safety for mypy compliance

### Fixed
- **Critical**: API authentication 403 errors due to incorrect header
- **Critical**: Invalid hardcoded API key
- Type annotation issues in `config.py` for mypy
- Environment variable loading in Windows

### Security
- Removed all hardcoded credentials
- Added validators to prevent path traversal attacks
- Implemented secure configuration storage

## [0.1.2] - 2025-01-28

### Added
- **Malware Collector**: Production-ready malware dataset collection from MalwareBazaar
- AES-encrypted ZIP extraction support via pyzipper library
- Advanced compression method handling (compression type 99)
- Retry logic for failed downloads (configurable, default: 2 attempts)
- Verbose debugging mode (`--verbose` or `-v` flag)
- Real-time progress tracking with success/failure counters
- Configurable sample collection via `--samples=N` argument
- Time estimation for collection runs
- Graceful keyboard interrupt handling with progress preservation

### Changed
- Increased default sample count from 20 to 50 per tag (~500 total samples)
- Improved ZIP extraction with multiple password attempts (infected, malware, none)
- Enhanced error messages with actionable suggestions
- Better metadata persistence (saves after each successful download)

### Fixed
- ZIP extraction failures with AES-encrypted archives from MalwareBazaar
- "That compression method is not supported" errors
- Type annotation issues for mypy compliance (`List[Optional[bytes]]`)
- Missing pyzipper dependency in requirements.txt
- Progress loss on manual interruption

### Technical
- Added `try_pyzipper_extract()` method for AES decryption
- Implemented automatic fallback from standard zipfile to pyzipper
- Added compression method detection and logging
- Enhanced verbose output for debugging extraction issues
- Improved error handling with specific exception types

## [0.1.1] - 2025-01-28

### Changed
- Removed all code comments for production-ready clean code
- Improved code readability and structure
- Enhanced error handling in CLI
- Better exception management across modules

### Fixed
- Fixed ml_trainer.py dataset path priority (test_dataset first)
- Fixed test_dataset_builder.py PE header generation
- Improved file validation in CLI commands
- Better error messages for missing modules

### Technical
- Code optimization and cleanup
- Eliminated redundant comments
- Enhanced module imports
- Better type safety

## [0.1.0] - 2025-01-27

### Added
- Initial release
- PE/ELF binary parsing
- Entropy calculation (global and per-section)
- Heuristic threat scoring
- String extraction (ASCII and wide strings)
- IOC detection (URLs, IPs, registry keys)
- Suspicious API/symbol detection
- Batch processing with parallel execution
- CLI interface
- ML feature extraction pipeline
- Random Forest classifier
- Isolation Forest anomaly detection
- Test dataset builder

### Features
- 100% detection rate on test dataset
- 0% false positive rate
- 16+ extracted features per sample
- High-performance Rust core
- Python integration via PyO3

### Known Issues
- Limited to synthetic test data
- ML models need larger training sets
- No dynamic analysis
- PE analysis more mature than ELF