import proteus
from pathlib import Path
from typing import List, Dict


class ProteusAnalyzer:
    def __init__(self):
        self.threshold = 60.0

    def analyze_single(self, file_path: str) -> Dict:
        result = proteus.analyze_file(file_path)
        return {
            "path": result.path,
            "type": result.file_type,
            "entropy": result.entropy,
            "score": result.threat_score,
            "indicators": result.suspicious_indicators,
            "verdict": "MALICIOUS" if result.threat_score > self.threshold else "CLEAN",
        }

    def analyze_directory(self, dir_path: str) -> List[Dict]:
        files = [str(p) for p in Path(dir_path).rglob("*") if p.is_file()]
        results = proteus.batch_analyze(files)

        return [
            {
                "path": r.path,
                "type": r.file_type,
                "entropy": r.entropy,
                "score": r.threat_score,
                "indicators": r.suspicious_indicators,
                "verdict": "MALICIOUS" if r.threat_score > self.threshold else "CLEAN",
            }
            for r in results
        ]
