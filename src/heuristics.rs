pub struct HeuristicScore {
    pub total_score: f64,
}

pub fn calculate_pe_score(
    entropy: f64,
    suspicious_imports: usize,
    num_sections: usize,
) -> HeuristicScore {
    let mut score_components = Vec::new();

    let entropy_score = if entropy > 7.8 {
        score_components.push(("Very high entropy (packed/encrypted)", 100.0));
        100.0
    } else if entropy > 7.5 {
        score_components.push(("High entropy (likely packed)", 85.0));
        85.0
    } else if entropy > 7.2 {
        score_components.push(("Elevated entropy", 70.0));
        70.0
    } else if entropy > 6.8 {
        score_components.push(("Moderate entropy", 40.0));
        40.0
    } else {
        (entropy / 8.0) * 30.0
    };

    let import_score = if suspicious_imports >= 5 {
        score_components.push(("Many suspicious imports", 100.0));
        100.0
    } else if suspicious_imports >= 3 {
        score_components.push(("Multiple suspicious imports", 70.0));
        70.0
    } else if suspicious_imports > 0 {
        (suspicious_imports as f64 * 25.0).min(100.0)
    } else {
        0.0
    };

    let section_score = if num_sections == 0 {
        score_components.push(("No sections (malformed)", 80.0));
        80.0
    } else if num_sections == 1 {
        score_components.push(("Single section (suspicious)", 60.0));
        60.0
    } else if num_sections == 2 {
        score_components.push(("Two sections (unusual)", 40.0));
        40.0
    } else if num_sections > 15 {
        score_components.push(("Too many sections", 50.0));
        50.0
    } else if !(3..=10).contains(&num_sections) {
        20.0
    } else {
        0.0
    };

    let total = (entropy_score * 0.6 + import_score * 0.3 + section_score * 0.1).min(100.0);

    HeuristicScore { total_score: total }
}

pub fn calculate_elf_score(
    entropy: f64,
    suspicious_symbols: usize,
    stripped: bool,
) -> HeuristicScore {
    let entropy_score = if entropy > 7.8 {
        100.0
    } else if entropy > 7.5 {
        85.0
    } else if entropy > 7.2 {
        70.0
    } else {
        (entropy / 8.0) * 50.0
    };

    let import_score = if suspicious_symbols >= 5 {
        100.0
    } else if suspicious_symbols >= 3 {
        70.0
    } else {
        (suspicious_symbols as f64 * 25.0).min(100.0)
    };

    let section_score = if stripped { 50.0 } else { 0.0 };

    let total = (entropy_score * 0.5 + import_score * 0.3 + section_score * 0.2).min(100.0);

    HeuristicScore { total_score: total }
}
