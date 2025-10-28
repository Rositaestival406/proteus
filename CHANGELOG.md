# Changelog

All notable changes to Proteus will be documented in this file.

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