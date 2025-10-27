import shutil
from pathlib import Path
from typing import List
import json


class CleanSampleCollector:
    def __init__(self, output_dir="dataset/clean"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.output_dir / "metadata.json"
        self.collected = {}

    def collect_windows_samples(self, count: int = 100) -> int:
        sources = [
            Path("C:/Windows/System32"),
            Path("C:/Windows/SysWOW64"),
            Path("C:/Program Files"),
            Path("C:/Program Files (x86)"),
        ]

        collected = 0

        for source in sources:
            if not source.exists():
                continue

            print(f"[*] Scanning: {source}")

            for exe_file in source.rglob("*.exe"):
                if collected >= count:
                    break

                if exe_file.stat().st_size > 100 * 1024 * 1024:
                    continue

                try:
                    dest = self.output_dir / exe_file.name

                    if dest.exists():
                        continue

                    shutil.copy2(exe_file, dest)

                    self.collected[exe_file.name] = {
                        "path": str(dest),
                        "original": str(exe_file),
                        "size": exe_file.stat().st_size,
                        "category": (
                            "windows_system"
                            if "Windows" in str(source)
                            else "application"
                        ),
                    }

                    print(f"    [+] {exe_file.name}")
                    collected += 1

                except Exception as e:
                    continue

            if collected >= count:
                break

        return collected

    def save_metadata(self):
        with open(self.metadata_file, "w") as f:
            json.dump(self.collected, f, indent=2)

    def get_statistics(self):
        return {
            "total": len(self.collected),
            "by_category": {
                "windows_system": sum(
                    1
                    for v in self.collected.values()
                    if v["category"] == "windows_system"
                ),
                "application": sum(
                    1 for v in self.collected.values() if v["category"] == "application"
                ),
            },
        }


def main():
    print("╔═══════════════════════════════════════╗")
    print("║   PROTEUS Clean Sample Collector      ║")
    print("╚═══════════════════════════════════════╝\n")

    collector = CleanSampleCollector()

    count = collector.collect_windows_samples(count=200)
    collector.save_metadata()

    stats = collector.get_statistics()

    print(f"\n[+] Collected {stats['total']} clean samples")
    print(f"    Windows system: {stats['by_category']['windows_system']}")
    print(f"    Applications: {stats['by_category']['application']}")
    print(f"\n[+] Saved to: {collector.output_dir}")


if __name__ == "__main__":
    main()
