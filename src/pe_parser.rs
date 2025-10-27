use goblin::pe::PE;
use std::fs;

pub struct PEAnalysis {
    pub entropy: f64,
    pub suspicious_imports: Vec<String>,
    pub num_sections: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub section_entropies: Vec<f64>,
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
        "CreateProcess",
        "OpenProcess",
        "ReadProcessMemory",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "InternetOpen",
    ];

    let mut suspicious_imports = Vec::new();
    let import_count = pe.imports.len();

    for import in &pe.imports {
        let import_name = import.name.as_ref();
        if suspicious_apis.contains(&import_name) {
            suspicious_imports.push(import_name.to_string());
        }
    }

    let export_count = pe.exports.len();

    let mut section_entropies = Vec::new();
    for section in &pe.sections {
        if let Ok(Some(data)) = section.data(&buffer) {
            section_entropies.push(crate::entropy::calculate_entropy(&data));
        }
    }

    Ok(PEAnalysis {
        entropy,
        suspicious_imports,
        num_sections: pe.sections.len(),
        import_count,
        export_count,
        section_entropies,
    })
}
