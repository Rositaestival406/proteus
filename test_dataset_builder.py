import os
import shutil
from pathlib import Path
from python.analyzer import ProteusAnalyzer


class TestDatasetBuilder:
    def __init__(self, output_dir="test_dataset"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.malicious_dir = self.output_dir / "malicious"
        self.clean_dir = self.output_dir / "clean"
        self.malicious_dir.mkdir(exist_ok=True)
        self.clean_dir.mkdir(exist_ok=True)

    def create_high_entropy_exe(self):
        import struct
        import random

        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = bytearray(20)
        coff_header[0:2] = struct.pack("<H", 0x014C)
        coff_header[2:4] = struct.pack("<H", 1)
        coff_header[16:18] = struct.pack("<H", 224)
        coff_header[18:20] = struct.pack("<H", 0x010B)

        optional_header = bytearray(224)
        optional_header[0:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x1000)
        optional_header[20:24] = struct.pack("<I", 0x1000)
        optional_header[40:44] = struct.pack("<I", 0x400000)
        optional_header[44:48] = struct.pack("<I", 0x1000)

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x2000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x2000)
        section_header[20:24] = struct.pack("<I", 0x400)
        section_header[36:40] = struct.pack("<I", 0x60000020)

        random_data = bytes([random.randint(0, 255) for _ in range(8192)])

        pe_file = (
            bytes(dos_header)
            + pe_signature
            + bytes(coff_header)
            + bytes(optional_header)
            + bytes(section_header)
            + random_data
        )

        test_path = self.malicious_dir / "suspicious_packed.exe"
        with open(test_path, "wb") as f:
            f.write(pe_file)

        print(f"[+] Created high-entropy PE file: {test_path}")
        return str(test_path)

    def collect_system_files(self, count=20):
        system_dirs = [
            Path("C:/Windows/System32"),
            Path("C:/Windows/SysWOW64"),
        ]

        collected = 0
        for sys_dir in system_dirs:
            if not sys_dir.exists():
                continue

            for exe_file in sys_dir.glob("*.exe"):
                if collected >= count:
                    break

                try:
                    dest = self.clean_dir / exe_file.name
                    if not dest.exists():
                        shutil.copy2(exe_file, dest)
                        print(f"[+] Copied clean file: {exe_file.name}")
                        collected += 1
                except Exception as e:
                    continue

            if collected >= count:
                break

        return collected

    def analyze_dataset(self):
        analyzer = ProteusAnalyzer()

        print("\n[*] Analyzing malicious samples...")
        malicious_results = []
        for file in self.malicious_dir.glob("*.exe"):
            try:
                result = analyzer.analyze_single(str(file))
                malicious_results.append(result)
                print(
                    f"    {file.name}: Score={result['score']:.2f}, Verdict={result['verdict']}"
                )
            except Exception as e:
                print(f"    {file.name}: ERROR - {e}")

        print("\n[*] Analyzing clean samples (first 20)...")
        clean_results = []
        for idx, file in enumerate(self.clean_dir.glob("*.exe")):
            if idx >= 20:
                break
            try:
                result = analyzer.analyze_single(str(file))
                clean_results.append(result)
                print(f"    {file.name}: Score={result['score']:.2f}")
            except Exception as e:
                print(f"    {file.name}: ERROR - {e}")

        return malicious_results, clean_results

    def generate_report(self, malicious_results, clean_results):
        print("\n╔═══════════════════════════════════════╗")
        print("║        Dataset Statistics             ║")
        print("╚═══════════════════════════════════════╝")
        print(f"\nMalicious samples: {len(malicious_results)}")
        if malicious_results:
            avg_mal = sum(r["score"] for r in malicious_results) / len(
                malicious_results
            )
            print(f"  Average score: {avg_mal:.2f}")
            high_threat = [r for r in malicious_results if r["verdict"] == "MALICIOUS"]
            print(
                f"  Detected as malicious: {len(high_threat)}/{len(malicious_results)}"
            )

        print(f"\nClean samples: {len(clean_results)}")
        if clean_results:
            avg_clean = sum(r["score"] for r in clean_results) / len(clean_results)
            print(f"  Average score: {avg_clean:.2f}")
            false_positives = [r for r in clean_results if r["verdict"] == "MALICIOUS"]
            print(f"  False positives: {len(false_positives)}/{len(clean_results)}")

        print("\n[*] Detection Summary:")
        if malicious_results:
            detected = len(
                [r for r in malicious_results if r["verdict"] == "MALICIOUS"]
            )
            print(
                f"  Detection rate: {detected}/{len(malicious_results)} ({detected*100/len(malicious_results):.1f}%)"
            )
        if clean_results:
            fp = len([r for r in clean_results if r["verdict"] == "MALICIOUS"])
            print(
                f"  False positive rate: {fp}/{len(clean_results)} ({fp*100/len(clean_results):.1f}%)"
            )


def main():
    print("╔═══════════════════════════════════════╗")
    print("║   PROTEUS Test Dataset Builder        ║")
    print("╚═══════════════════════════════════════╝\n")

    builder = TestDatasetBuilder()

    print("[*] Creating test malware samples...")
    builder.create_high_entropy_exe()

    print("\n[*] Collecting clean system files...")
    count = builder.collect_system_files(count=20)
    print(f"[+] Collected {count} clean files")

    mal_results, clean_results = builder.analyze_dataset()
    builder.generate_report(mal_results, clean_results)


if __name__ == "__main__":
    main()
