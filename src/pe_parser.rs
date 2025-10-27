use goblin::pe::PE;
use std::fs;

pub struct PEAnalysis {
    pub entropy: f64,
    pub suspicious_imports: Vec<String>,
    pub num_sections: usize,
}

pub fn analyze_pe(path: &str) -> Result<PEAnalysis, Box<dyn std::error::Error>> {
    let buffer = fs::read(path)?;
    let pe = PE::parse(&buffer)?;

    let entropy = crate::entropy::calculate_entropy(&buffer);

    let suspicious_apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibrary",
        "GetProcAddress",
        "WinExec",
        "ShellExecute",
        "URLDownloadToFile",
    ];

    let mut suspicious_imports = Vec::new();
    for import in &pe.imports {
        let import_name = import.name.as_ref();
        if suspicious_apis.contains(&import_name) {
            suspicious_imports.push(import_name.to_string());
        }
    }

    Ok(PEAnalysis {
        entropy,
        suspicious_imports,
        num_sections: pe.sections.len(),
    })
}
