import sys
import json
from pathlib import Path
from typing import Optional
from python.analyzer import ProteusAnalyzer
from python.ml_detector import ProteusMLDetector
import proteus

def print_banner():
    banner = """
╔═══════════════════════════════════════╗
║         PROTEUS v0.1.0                ║
║   Zero-Day Static Analysis Engine    ║
╚═══════════════════════════════════════╝
"""
    print(banner)

def analyze_file_cmd(file_path: str, show_strings: bool = False):
    analyzer = ProteusAnalyzer()
    try:
        result = analyzer.analyze_single(file_path)
        print(f"\n[*] Analysis: {file_path}")
        print(f"[+] Type: {result['type']}")
        print(f"[+] Entropy: {result['entropy']:.2f}")
        print(f"[+] Threat Score: {result['score']:.2f}/100")
        print(f"[+] Verdict: {result['verdict']}")
        
        if result['indicators']:
            print(f"[!] Suspicious Indicators:")
            for indicator in result['indicators']:
                print(f"    - {indicator}")
        
        if show_strings:
            print(f"\n[*] String Analysis:")
            string_result = proteus.extract_strings_from_file(file_path)
            
            print(f"[+] Total strings: {string_result.total_strings}")
            print(f"[+] Encoded strings: {string_result.encoded_strings}")
            
            if string_result.urls:
                print(f"\n[!] URLs ({len(string_result.urls)}):")
                for url in string_result.urls[:5]:
                    print(f"    {url}")
            
            if string_result.ips:
                print(f"\n[!] IPs ({len(string_result.ips)}):")
                for ip in string_result.ips[:5]:
                    print(f"    {ip}")
            
            if string_result.suspicious_strings:
                print(f"\n[!] Suspicious strings ({len(string_result.suspicious_strings)}):")
                for s in string_result.suspicious_strings[:10]:
                    print(f"    {s}")
            
    except Exception as e:
        print(f"[!] Error: {e}")

def analyze_directory_cmd(dir_path: str, output: Optional[str] = None):
    analyzer = ProteusAnalyzer()
    try:
        results = analyzer.analyze_directory(dir_path)
        
        malicious = [r for r in results if r['verdict'] == 'MALICIOUS']
        clean = [r for r in results if r['verdict'] == 'CLEAN']
        
        print(f"\n[*] Scanned: {len(results)} files")
        print(f"[+] Clean: {len(clean)}")
        print(f"[!] Malicious: {len(malicious)}")
        
        if malicious:
            print(f"\n[!] Malicious Files:")
            for r in malicious:
                print(f"    {r['path']} (Score: {r['score']:.2f})")
        
        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[*] Results saved: {output}")
            
    except Exception as e:
        print(f"[!] Error: {e}")

def strings_cmd(file_path: str):
    try:
        result = proteus.extract_strings_from_file(file_path)
        
        print(f"\n[*] String Analysis: {file_path}")
        print(f"[+] Total strings: {result.total_strings}")
        print(f"[+] Encoded strings: {result.encoded_strings}")
        
        if result.urls:
            print(f"\n[!] URLs found ({len(result.urls)}):")
            for url in result.urls[:10]:
                print(f"    {url}")
        
        if result.ips:
            print(f"\n[!] IP addresses ({len(result.ips)}):")
            for ip in result.ips[:10]:
                print(f"    {ip}")
        
        if result.registry_keys:
            print(f"\n[!] Registry keys ({len(result.registry_keys)}):")
            for key in result.registry_keys[:10]:
                print(f"    {key}")
        
        if result.suspicious_strings:
            print(f"\n[!] Suspicious strings ({len(result.suspicious_strings)}):")
            for s in result.suspicious_strings[:20]:
                print(f"    {s}")
        
        if result.file_paths:
            print(f"\n[*] File paths ({len(result.file_paths)}):")
            for path in result.file_paths[:10]:
                print(f"    {path}")
                
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python cli.py file <path> [--strings]")
        print("  python cli.py dir <path> [--output results.json]")
        print("  python cli.py strings <path>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "file":
        if len(sys.argv) < 3:
            print("[!] Error: File path required")
            sys.exit(1)
        show_strings = "--strings" in sys.argv
        analyze_file_cmd(sys.argv[2], show_strings)
        
    elif command == "dir":
        if len(sys.argv) < 3:
            print("[!] Error: Directory path required")
            sys.exit(1)
        output = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--output" else None
        analyze_directory_cmd(sys.argv[2], output)
    
    elif command == "strings":
        if len(sys.argv) < 3:
            print("[!] Error: File path required")
            sys.exit(1)
        strings_cmd(sys.argv[2])
        
    else:
        print(f"[!] Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()