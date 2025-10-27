#!/usr/bin/env python3

import os
import shutil
import struct
import random
from pathlib import Path


class TestDatasetBuilder:
    def __init__(self, output_dir="test_dataset"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.malicious_dir = self.output_dir / "malicious"
        self.clean_dir = self.output_dir / "clean"
        self.malicious_dir.mkdir(exist_ok=True)
        self.clean_dir.mkdir(exist_ok=True)

    def create_pe_header(self):
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

        return (
            bytes(dos_header)
            + pe_signature
            + bytes(coff_header)
            + bytes(optional_header)
            + bytes(section_header)
        )

    def create_high_entropy_sample(self, sample_id: int):
        header = self.create_pe_header()
        data_size = random.randint(8192, 16384)
        random_data = bytes([random.randint(0, 255) for _ in range(data_size)])
        return header + random_data

    def create_suspicious_strings_sample(self, sample_id: int):
        header = self.create_pe_header()

        suspicious_strings = [
            b"VirtualAlloc\x00",
            b"WriteProcessMemory\x00",
            b"CreateRemoteThread\x00",
            b"cmd.exe /c powershell\x00",
            b"http://malicious-domain.com/payload\x00",
            b"192.168.1.100\x00",
            b"HKEY_LOCAL_MACHINE\\Software\\Evil\x00",
            b"keylogger.dll\x00",
            b"ransomware\x00",
            b"C:\\Windows\\Temp\\malware.exe\x00",
        ]

        string_data = b"".join(suspicious_strings)
        padding_size = random.randint(4096, 8192)
        padding = bytes([random.randint(32, 126) for _ in range(padding_size)])

        return header + string_data + padding

    def create_low_entropy_sample(self, sample_id: int):
        header = self.create_pe_header()
        pattern = bytes([0x90, 0x41, 0x42, 0x43]) * 2048
        return header + pattern

    def create_mixed_sample(self, sample_id: int):
        header = self.create_pe_header()
        low_entropy = bytes([0x00] * 2048)
        high_entropy = bytes([random.randint(0, 255) for _ in range(4096)])
        medium_entropy = bytes([random.randint(32, 126) for _ in range(2048)])
        return header + low_entropy + high_entropy + medium_entropy

    def create_high_entropy_samples(self, count=10):
        print(f"[*] Creating {count} synthetic malware samples...")

        sample_types = [
            ("high_entropy", self.create_high_entropy_sample),
            ("suspicious_strings", self.create_suspicious_strings_sample),
            ("low_entropy", self.create_low_entropy_sample),
            ("mixed", self.create_mixed_sample),
        ]

        for i in range(count):
            sample_type_name, sample_func = random.choice(sample_types)
            sample_data = sample_func(i)
            filename = f"{sample_type_name}_{i}.exe"
            filepath = self.malicious_dir / filename

            with open(filepath, "wb") as f:
                f.write(sample_data)

            print(f"    [+] Created: {filename}")

    def collect_system_files(self, count=50):
        system_dirs = [
            Path("C:/Windows/System32"),
            Path("C:/Windows/SysWOW64"),
        ]

        collected = 0

        for sys_dir in system_dirs:
            if not sys_dir.exists():
                continue

            print(f"[*] Scanning: {sys_dir}")

            exe_files = list(sys_dir.glob("*.exe"))
            random.shuffle(exe_files)

            for exe_file in exe_files:
                if collected >= count:
                    break

                if exe_file.stat().st_size > 10 * 1024 * 1024:
                    continue

                try:
                    dest = self.clean_dir / exe_file.name
                    if not dest.exists():
                        shutil.copy2(exe_file, dest)
                        print(f"    [+] {exe_file.name}")
                        collected += 1
                except Exception:
                    continue

            if collected >= count:
                break

        return collected

    def analyze_dataset(self):
        print("\n[*] Analyzing dataset...")

        try:
            from python.analyzer import ProteusAnalyzer

            analyzer = ProteusAnalyzer()

            print("\n[*] Analyzing malicious samples:")
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

            print(f"\n[*] Analyzing clean samples...")
            clean_results = []
            for file in self.clean_dir.glob("*.exe"):
                try:
                    result = analyzer.analyze_single(str(file))
                    clean_results.append(result)
                except Exception as e:
                    print(f"    {file.name}: ERROR - {e}")

            print(f"[+] Analyzed {len(clean_results)} clean files")

            return malicious_results, clean_results

        except ImportError:
            print("[!] Cannot analyze: proteus module not built")
            print("[!] Run: maturin develop --release")
            return [], []

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
            detection_rate = detected * 100 / len(malicious_results)
            print(
                f"  Detection rate: {detected}/{len(malicious_results)} ({detection_rate:.1f}%)"
            )

        if clean_results:
            fp = len([r for r in clean_results if r["verdict"] == "MALICIOUS"])
            fp_rate = fp * 100 / len(clean_results)
            print(f"  False positive rate: {fp}/{len(clean_results)} ({fp_rate:.1f}%)")


def main():
    print("╔═══════════════════════════════════════╗")
    print("║   PROTEUS Test Dataset Builder        ║")
    print("╚═══════════════════════════════════════╝\n")

    builder = TestDatasetBuilder()

    builder.create_high_entropy_samples(count=10)

    print("\n[*] Collecting clean system files...")
    count = builder.collect_system_files(count=50)
    print(f"[+] Collected {count} clean files")

    mal_results, clean_results = builder.analyze_dataset()
    builder.generate_report(mal_results, clean_results)


if __name__ == "__main__":
    main()
