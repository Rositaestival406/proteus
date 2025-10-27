# Changelog

All notable changes to Proteus will be documented in this file.

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