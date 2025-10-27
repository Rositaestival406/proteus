#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use rayon::prelude::*;

#[pyclass]
pub struct FileAnalysis {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub file_type: String,
    #[pyo3(get)]
    pub entropy: f64,
    #[pyo3(get)]
    pub threat_score: f64,
    #[pyo3(get)]
    pub suspicious_indicators: Vec<String>,
}

#[pyclass]
pub struct StringAnalysisResult {
    #[pyo3(get)]
    pub urls: Vec<String>,
    #[pyo3(get)]
    pub ips: Vec<String>,
    #[pyo3(get)]
    pub registry_keys: Vec<String>,
    #[pyo3(get)]
    pub suspicious_strings: Vec<String>,
    #[pyo3(get)]
    pub file_paths: Vec<String>,
    #[pyo3(get)]
    pub encoded_strings: usize,
    #[pyo3(get)]
    pub total_strings: usize,
}

#[pyfunction]
pub fn analyze_file(path: String) -> PyResult<FileAnalysis> {
    let file_type = detect_file_type(&path);

    let (entropy, threat_score, indicators) = match file_type.as_str() {
        "PE" => {
            let analysis = crate::pe_parser::analyze_pe(&path)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let score = crate::heuristics::calculate_pe_score(
                analysis.entropy,
                analysis.suspicious_imports.len(),
                analysis.num_sections,
            );
            (
                analysis.entropy,
                score.total_score,
                analysis.suspicious_imports,
            )
        }
        "ELF" => {
            let analysis = crate::elf_parser::analyze_elf(&path)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let score = crate::heuristics::calculate_elf_score(
                analysis.entropy,
                analysis.suspicious_symbols.len(),
                analysis.stripped,
            );
            (
                analysis.entropy,
                score.total_score,
                analysis.suspicious_symbols,
            )
        }
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Unsupported file type",
            ))
        }
    };

    Ok(FileAnalysis {
        path,
        file_type,
        entropy,
        threat_score,
        suspicious_indicators: indicators,
    })
}

#[pyfunction]
pub fn batch_analyze(paths: Vec<String>) -> PyResult<Vec<FileAnalysis>> {
    let results: Vec<_> = paths
        .par_iter()
        .filter_map(|path| analyze_file(path.clone()).ok())
        .collect();

    Ok(results)
}

#[pyfunction]
pub fn extract_strings_from_file(path: String) -> PyResult<StringAnalysisResult> {
    use std::fs;

    let data = fs::read(&path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let analysis = crate::string_extractor::analyze_strings(&data);

    Ok(StringAnalysisResult {
        urls: analysis.urls,
        ips: analysis.ips,
        registry_keys: analysis.registry_keys,
        suspicious_strings: analysis.suspicious_strings,
        file_paths: analysis.file_paths,
        encoded_strings: analysis.encoded_strings,
        total_strings: analysis.total_strings,
    })
}

fn detect_file_type(path: &str) -> String {
    use std::fs::File;
    use std::io::Read;

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return "Unknown".to_string(),
    };

    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return "Unknown".to_string();
    }

    if magic[0] == 0x4D && magic[1] == 0x5A {
        "PE".to_string()
    } else if magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46 {
        "ELF".to_string()
    } else {
        "Unknown".to_string()
    }
}
