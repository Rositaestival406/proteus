import proteus

file_path = "C:\\Windows\\System32\\notepad.exe"

print(f"[*] Analyzing strings in: {file_path}\n")

result = proteus.extract_strings_from_file(file_path)

print(f"Total strings found: {result.total_strings}")
print(f"Encoded strings: {result.encoded_strings}\n")

if result.urls:
    print(f"[!] URLs found ({len(result.urls)}):")
    for url in result.urls[:10]:
        print(f"    {url}")

if result.ips:
    print(f"\n[!] IP addresses found ({len(result.ips)}):")
    for ip in result.ips[:10]:
        print(f"    {ip}")

if result.registry_keys:
    print(f"\n[!] Registry keys found ({len(result.registry_keys)}):")
    for key in result.registry_keys[:10]:
        print(f"    {key}")

if result.suspicious_strings:
    print(f"\n[!] Suspicious strings found ({len(result.suspicious_strings)}):")
    for s in result.suspicious_strings[:15]:
        print(f"    {s}")

if result.file_paths:
    print(f"\n[*] File paths found ({len(result.file_paths)}):")
    for path in result.file_paths[:10]:
        print(f"    {path}")
