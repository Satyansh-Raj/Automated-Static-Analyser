#!/usr/bin/env python3
"""
Static Analysis JSON to Text Parser
Converts JSON output from malware_static_analyzer.py to human-readable text format.

Usage:
    python3 static_analysis_parser.py analysis_results.json
    python3 static_analysis_parser.py analysis_results.json -o report.txt
    python3 static_analysis_parser.py analysis_results.json --output report.txt
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime


class StaticAnalysisParser:
    """Parse static analysis JSON and convert to human-readable text."""
    
    # Known suspicious DLLs that are commonly used by malware
    SUSPICIOUS_DLLS = {
        'urlmon.dll': 'URL moniker - file downloads, often malware dropper indicator',
        'wininet.dll': 'Internet functions - HTTP/FTP communication for C2 or downloads',
        'ws2_32.dll': 'Winsock - raw network communication, C2, data exfiltration',
        'wsock32.dll': 'Winsock (legacy) - network communication',
        'winhttp.dll': 'HTTP services - web requests for C2 or downloads',
        'crypt32.dll': 'Cryptography - encryption/decryption of payloads or data',
        'advapi32.dll': 'Advanced API - registry, services, security tokens',
        'ntdll.dll': 'NT layer - low-level system calls, often for evasion',
        'shell32.dll': 'Shell functions - execute commands, drop files',
        'user32.dll': 'User interface - keylogging, screen capture',
        'gdi32.dll': 'Graphics - screen capture capabilities',
        'psapi.dll': 'Process status - process enumeration',
        'dbghelp.dll': 'Debug helper - memory dumps, anti-analysis',
        'cabinet.dll': 'Cabinet files - extraction of embedded payloads',
        'cryptsp.dll': 'Crypto service provider - encryption operations',
        'bcrypt.dll': 'Crypto next gen - modern encryption APIs',
        'ncrypt.dll': 'Key storage - credential access',
        'samlib.dll': 'SAM library - credential dumping',
        'vaultcli.dll': 'Credential vault - password theft',
        'wtsapi32.dll': 'Terminal services - RDP session manipulation',
        'secur32.dll': 'Security - authentication manipulation',
        'netapi32.dll': 'Network management - lateral movement',
        'dnsapi.dll': 'DNS API - DNS tunneling, C2 communication',
        'iphlpapi.dll': 'IP helper - network reconnaissance',
        'mpr.dll': 'Multiple provider router - network drives, credentials',
        'shlwapi.dll': 'Shell lightweight - path manipulation',
        'amsi.dll': 'Antimalware Scan Interface - evasion target',
    }
    
    # Suspicious API patterns
    SUSPICIOUS_APIS = [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
        'NtCreateThread', 'RtlCreateUserThread', 'QueueUserAPC',
        'SetThreadContext', 'GetThreadContext', 'SuspendThread', 'ResumeThread',
        'OpenProcess', 'CreateProcess', 'ShellExecute', 'WinExec',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
        'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
        'RegSetValue', 'RegCreateKey', 'CreateService', 'StartService',
        'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'URLDownload',
        'WSAStartup', 'socket', 'connect', 'send', 'recv',
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
        'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValue',
        'CredEnumerate', 'CredRead', 'LsaRetrievePrivateData',
        'MiniDumpWriteDump', 'EnumProcesses', 'EnumProcessModules',
        'GetProcAddress', 'LoadLibrary', 'LdrLoadDll',
        'NtUnmapViewOfSection', 'NtMapViewOfSection',
    ]
    
    def __init__(self, json_data: dict):
        self.data = json_data
        self.output_lines = []
    
    def add_line(self, text: str = ""):
        """Add a line to output."""
        self.output_lines.append(text)
    
    def add_section(self, title: str, char: str = "="):
        """Add a section header."""
        self.add_line("")
        self.add_line(char * 80)
        self.add_line(f" {title}")
        self.add_line(char * 80)
    
    def add_subsection(self, title: str):
        """Add a subsection header."""
        self.add_line("")
        self.add_line(f"--- {title} ---")
    
    def safe_get(self, *keys, default="N/A"):
        """Safely get nested dictionary values."""
        value = self.data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value if value not in [None, "", [], {}] else default
    
    def format_size(self, size_bytes):
        """Format bytes to human-readable size."""
        if isinstance(size_bytes, str):
            return size_bytes
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"
    
    def parse(self) -> str:
        """Parse all sections and return formatted text."""
        self.parse_header()
        self.parse_metadata()
        self.parse_hashes()
        self.parse_strings()
        self.parse_pe_analysis()
        self.parse_imports_exports()
        self.parse_resources()
        self.parse_rich_header()
        self.parse_pdb_info()
        self.parse_tls_callbacks()
        self.parse_overlay()
        self.parse_version_info()
        self.parse_packer_detection()
        self.parse_entropy()
        self.parse_anti_analysis()
        self.parse_language_detection()
        self.parse_capability_mapping()
        self.parse_yara_matches()
        self.parse_authenticode()
        self.parse_import_categories()
        self.parse_entry_point_analysis()
        self.parse_config_detection()
        self.parse_instruction_anti_debug()
        self.parse_threat_intel()
        # Context-aware analysis (NEW)
        self.parse_installer_info()
        self.parse_benign_indicators()
        # Final verdict
        self.parse_risk_score()
        self.parse_why_suspicious()
        self.parse_hex_dump()
        self.parse_footer()
        
        return "\n".join(self.output_lines)
    
    def parse_header(self):
        """Parse report header."""
        self.add_line("=" * 80)
        self.add_line("                    STATIC MALWARE ANALYSIS REPORT")
        self.add_line("=" * 80)
        
        timestamp = self.safe_get("timestamp")
        if timestamp != "N/A":
            try:
                dt = datetime.fromisoformat(timestamp)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        
        self.add_line(f"Report Generated: {timestamp}")
        self.add_line(f"File Analyzed: {self.safe_get('file_path')}")
    
    def parse_metadata(self):
        """Parse file metadata section."""
        self.add_section("FILE METADATA")
        
        metadata = self.data.get("metadata", {})
        
        self.add_line(f"  Filename:          {metadata.get('filename', 'N/A')}")
        self.add_line(f"  File Size:         {metadata.get('file_size_human', 'N/A')} ({metadata.get('file_size', 'N/A')} bytes)")
        self.add_line(f"  File Type:         {metadata.get('file_type', 'N/A')}")
        self.add_line(f"  MIME Type:         {metadata.get('mime_type', 'N/A')}")
        self.add_line(f"  Creation Time:     {metadata.get('creation_time', 'N/A')}")
        self.add_line(f"  Modification Time: {metadata.get('modification_time', 'N/A')}")
        self.add_line(f"  Access Time:       {metadata.get('access_time', 'N/A')}")
        self.add_line(f"  Permissions:       {metadata.get('permissions', 'N/A')}")
    
    def parse_hashes(self):
        """Parse cryptographic hashes section."""
        self.add_section("CRYPTOGRAPHIC HASHES")
        
        hashes = self.data.get("hashes", {})
        
        self.add_line(f"  MD5:       {hashes.get('md5', 'N/A')}")
        self.add_line(f"  SHA1:      {hashes.get('sha1', 'N/A')}")
        self.add_line(f"  SHA256:    {hashes.get('sha256', 'N/A')}")
        self.add_line(f"  SHA512:    {hashes.get('sha512', 'N/A')}")
        self.add_line(f"  SHA3-256:  {hashes.get('sha3_256', 'N/A')}")
        self.add_line(f"  BLAKE2b:   {hashes.get('blake2b', 'N/A')}")
        self.add_line(f"  ssdeep:    {hashes.get('ssdeep', 'N/A')}")
        self.add_line(f"  CRC32:     {hashes.get('crc32', 'N/A')}")
    
    def parse_strings(self):
        """Parse extracted strings section."""
        self.add_section("STRING ANALYSIS")
        
        strings = self.data.get("strings", {})
        
        self.add_line(f"  Total Strings:   {strings.get('total_strings', 0)}")
        self.add_line(f"  ASCII Strings:   {strings.get('ascii_strings', 0)}")
        self.add_line(f"  Unicode Strings: {strings.get('unicode_strings', 0)}")
        
        # URLs
        urls = strings.get("urls", [])
        if urls:
            self.add_subsection("URLs Found [SUSPICIOUS - Potential C2/Download]")
            for url in urls[:20]:  # Limit to 20
                self.add_line(f"    [SUSPICIOUS] {url}")
        
        # IP Addresses
        ips = strings.get("ip_addresses", [])
        if ips:
            self.add_subsection("IP Addresses Found [SUSPICIOUS - Potential C2]")
            for ip in ips[:20]:
                self.add_line(f"    [SUSPICIOUS] {ip}")
        
        # Email Addresses
        emails = strings.get("emails", [])
        if emails:
            self.add_subsection("Email Addresses Found")
            for email in emails[:20]:
                self.add_line(f"    - {email}")
        
        # Registry Keys
        registry = strings.get("registry_keys", [])
        if registry:
            self.add_subsection("Registry Keys Found [SUSPICIOUS - Potential Persistence]")
            for key in registry[:20]:
                self.add_line(f"    [SUSPICIOUS] {key}")
        
        # File Paths
        paths = strings.get("file_paths", [])
        if paths:
            self.add_subsection("File Paths Found")
            for path in paths[:20]:
                self.add_line(f"    - {path}")
        
        # DLL References
        dlls = strings.get("dll_references", [])
        if dlls:
            self.add_subsection("DLL References")
            for dll in dlls[:20]:
                dll_lower = dll.lower()
                if dll_lower in self.SUSPICIOUS_DLLS:
                    self.add_line(f"    [SUSPICIOUS] {dll} - {self.SUSPICIOUS_DLLS[dll_lower]}")
                else:
                    self.add_line(f"    - {dll}")
        
        # API Calls
        api_calls = strings.get("api_calls", [])
        if api_calls:
            self.add_subsection("API Calls Found in Strings")
            for api in api_calls[:20]:
                is_suspicious = any(sus_api.lower() in api.lower() for sus_api in self.SUSPICIOUS_APIS)
                if is_suspicious:
                    self.add_line(f"    [SUSPICIOUS] {api}")
                else:
                    self.add_line(f"    - {api}")
        
        # Interesting Strings
        interesting = strings.get("interesting_strings", [])
        if interesting:
            self.add_subsection("Interesting Strings [SUSPICIOUS]")
            for s in interesting[:20]:
                self.add_line(f"    [SUSPICIOUS] {s}")
        
        # Crypto Indicators
        crypto = strings.get("crypto_indicators", [])
        if crypto:
            self.add_subsection("Cryptocurrency/Crypto Indicators [SUSPICIOUS - Potential Ransomware]")
            for c in crypto[:20]:
                self.add_line(f"    [SUSPICIOUS] {c}")
    
    def parse_pe_analysis(self):
        """Parse PE analysis section."""
        pe = self.data.get("pe_analysis", {})
        
        if not pe:
            self.add_section("PE ANALYSIS")
            self.add_line("  [Not a PE file or PE analysis not performed]")
            return
        
        self.add_section("PE ANALYSIS")
        
        # Header info
        header = pe.get("header", {})
        if header:
            self.add_subsection("PE Header")
            self.add_line(f"    Machine:              {header.get('machine', 'N/A')}")
            self.add_line(f"    Number of Sections:   {header.get('number_of_sections', 'N/A')}")
            self.add_line(f"    Timestamp:            {header.get('time_date_stamp', 'N/A')}")
            self.add_line(f"    Characteristics:      {header.get('characteristics', 'N/A')}")
            self.add_line(f"    Optional Header Magic: {header.get('optional_header_magic', 'N/A')}")
            self.add_line(f"    Subsystem:            {header.get('subsystem', 'N/A')}")
            self.add_line(f"    DLL Characteristics:  {header.get('dll_characteristics', 'N/A')}")
            self.add_line(f"    Size of Image:        {header.get('size_of_image', 'N/A')}")
            self.add_line(f"    Entry Point:          {header.get('entry_point', 'N/A')}")
            self.add_line(f"    Image Base:           {header.get('image_base', 'N/A')}")
            self.add_line(f"    Checksum:             {header.get('checksum', 'N/A')}")
        
        # Imphash
        imphash = pe.get("imphash", "N/A")
        self.add_line(f"    Import Hash (imphash): {imphash}")
        
        # Sections
        sections = pe.get("sections", [])
        if sections:
            self.add_subsection("PE Sections")
            self.add_line(f"    {'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8} {'Suspicious'}")
            self.add_line(f"    {'-'*10} {'-'*12} {'-'*10} {'-'*10} {'-'*8} {'-'*10}")
            for section in sections:
                name = section.get('name', 'N/A')[:10]
                vaddr = section.get('virtual_address', 'N/A')
                vsize = section.get('virtual_size', 'N/A')
                rsize = section.get('raw_size', 'N/A')
                entropy = section.get('entropy', 0)
                suspicious = "YES" if section.get('suspicious', False) else "No"
                self.add_line(f"    {name:<10} {vaddr:<12} {vsize:<10} {rsize:<10} {entropy:<8.2f} {suspicious}")
        
        # Anomalies
        anomalies = pe.get("anomalies", [])
        if anomalies:
            self.add_subsection("PE Anomalies Detected")
            for anomaly in anomalies:
                self.add_line(f"    [!] {anomaly}")
    
    def parse_imports_exports(self):
        """Parse imports and exports section."""
        ie = self.data.get("imports_exports", {})
        
        if not ie:
            return
        
        self.add_section("IMPORTS & EXPORTS")
        
        self.add_line(f"  Total Imports: {ie.get('total_imports', 0)}")
        self.add_line(f"  Total Exports: {ie.get('total_exports', 0)}")
        
        # Suspicious imports
        suspicious = ie.get("suspicious_imports", [])
        if suspicious:
            self.add_subsection("Suspicious Imports")
            for imp in suspicious:
                self.add_line(f"    [!] {imp}")
        
        # Imports by DLL
        imports = ie.get("imports", {})
        if imports:
            self.add_subsection("Imports by DLL")
            for dll, funcs in imports.items():
                if isinstance(funcs, list):
                    func_count = len(funcs)
                    dll_lower = dll.lower()
                    if dll_lower in self.SUSPICIOUS_DLLS:
                        self.add_line(f"    [SUSPICIOUS] {dll}: {func_count} function(s) - {self.SUSPICIOUS_DLLS[dll_lower]}")
                    else:
                        self.add_line(f"    {dll}: {func_count} function(s)")
        
        # Exports
        exports = ie.get("exports", [])
        if exports:
            self.add_subsection("Exports")
            for exp in exports[:20]:
                name = exp.get('name', 'N/A')
                addr = exp.get('address', 'N/A')
                self.add_line(f"    {name} @ {addr}")
    
    def parse_resources(self):
        """Parse PE resources section."""
        resources = self.data.get("resources", {})
        
        if not resources or resources.get("total_resources", 0) == 0:
            return
        
        self.add_section("PE RESOURCES")
        
        self.add_line(f"  Total Resources: {resources.get('total_resources', 0)}")
        
        res_list = resources.get("resources_list", [])
        if res_list:
            self.add_subsection("Resource Details")
            for res in res_list[:20]:
                self.add_line(f"    Type: {res.get('type', 'N/A')}, ID: {res.get('id', 'N/A')}, "
                            f"Size: {res.get('size', 'N/A')}, Entropy: {res.get('entropy', 0):.2f}")
    
    def parse_rich_header(self):
        """Parse Rich Header section."""
        rich = self.data.get("rich_header", {})
        
        if not rich:
            return
        
        self.add_section("RICH HEADER")
        
        present = rich.get("present", False)
        self.add_line(f"  Rich Header Present: {'Yes' if present else 'No'}")
        
        if present:
            self.add_line(f"  Rich Hash: {rich.get('rich_hash', 'N/A')}")
            
            toolchain = rich.get("toolchain_info", [])
            if toolchain:
                self.add_subsection("Toolchain Information")
                for tool in toolchain:
                    self.add_line(f"    - {tool}")
    
    def parse_pdb_info(self):
        """Parse PDB debug info section."""
        pdb = self.data.get("pdb_info", {})
        
        if not pdb or not pdb.get("pdb_path"):
            return
        
        self.add_section("PDB DEBUG INFORMATION")
        
        self.add_line(f"  PDB Path:            {pdb.get('pdb_path', 'N/A')}")
        self.add_line(f"  PDB Filename:        {pdb.get('pdb_filename', 'N/A')}")
        self.add_line(f"  Potential Username:  {pdb.get('potential_username', 'N/A')}")
        self.add_line(f"  Potential Project:   {pdb.get('potential_project', 'N/A')}")
        self.add_line(f"  GUID:                {pdb.get('guid', 'N/A')}")
        self.add_line(f"  Age:                 {pdb.get('age', 'N/A')}")
    
    def parse_tls_callbacks(self):
        """Parse TLS callbacks section."""
        tls = self.data.get("tls_callbacks", {})
        
        if not tls:
            return
        
        self.add_section("TLS CALLBACKS")
        
        has_tls = tls.get("has_tls", False)
        self.add_line(f"  Has TLS Directory: {'Yes' if has_tls else 'No'}")
        
        if has_tls:
            pre_entry = tls.get("pre_entry_execution", False)
            self.add_line(f"  Pre-Entry Execution: {'Yes [SUSPICIOUS]' if pre_entry else 'No'}")
            self.add_line(f"  Parsing Status: {tls.get('parsing_status', 'N/A')}")
            
            callbacks = tls.get("callbacks", [])
            if callbacks:
                self.add_line(f"  Callbacks Found: {len(callbacks)}")
                for cb in callbacks:
                    self.add_line(f"    - Address: {cb.get('address', 'N/A')} (RVA: {cb.get('rva', 'N/A')})")
            
            note = tls.get("analysis_note")
            if note:
                self.add_line(f"  Analysis Note: {note}")
    
    def parse_overlay(self):
        """Parse overlay section."""
        overlay = self.data.get("overlay", {})
        
        if not overlay or not overlay.get("has_overlay", False):
            return
        
        self.add_section("OVERLAY DATA")
        
        self.add_line(f"  Has Overlay:      Yes")
        self.add_line(f"  Overlay Offset:   {overlay.get('overlay_offset', 'N/A')}")
        self.add_line(f"  Overlay Size:     {overlay.get('overlay_size', 'N/A')} bytes")
        self.add_line(f"  Overlay Ratio:    {overlay.get('overlay_ratio', 0):.2f}%")
        self.add_line(f"  Overlay Entropy:  {overlay.get('overlay_entropy', 0):.4f}")
        self.add_line(f"  Magic Bytes:      {overlay.get('magic_bytes', 'N/A')}")
        self.add_line(f"  Possible Content: {overlay.get('possible_content', 'N/A')}")
        suspicious_overlay = overlay.get('suspicious', False)
        if suspicious_overlay:
            self.add_line(f"  Suspicious:       Yes [SUSPICIOUS - Large or high-entropy overlay may contain hidden payload]")
        else:
            self.add_line(f"  Suspicious:       No")
    
    def parse_version_info(self):
        """Parse version info section."""
        ver = self.data.get("version_info", {})
        
        if not ver or not ver.get("has_version_info", False):
            return
        
        self.add_section("VERSION INFORMATION")
        
        self.add_line(f"  File Version:       {ver.get('file_version', 'N/A')}")
        self.add_line(f"  Product Version:    {ver.get('product_version', 'N/A')}")
        self.add_line(f"  Company Name:       {ver.get('company_name', 'N/A')}")
        self.add_line(f"  Product Name:       {ver.get('product_name', 'N/A')}")
        self.add_line(f"  File Description:   {ver.get('file_description', 'N/A')}")
        self.add_line(f"  Original Filename:  {ver.get('original_filename', 'N/A')}")
        self.add_line(f"  Internal Name:      {ver.get('internal_name', 'N/A')}")
        self.add_line(f"  Legal Copyright:    {ver.get('legal_copyright', 'N/A')}")
        
        mismatch = ver.get("filename_mismatch", False)
        if mismatch:
            mismatch_type = ver.get("mismatch_type", "unknown")
            if mismatch_type == "suspicious_masquerade":
                self.add_line(f"  [!] SUSPICIOUS: Filename masquerading detected (brand/product mismatch)")
            elif mismatch_type == "benign_rename":
                self.add_line(f"  [i] Filename mismatch (benign - common for installer wrappers)")
            else:
                self.add_line(f"  [?] Filename mismatch detected (indeterminate)")
    
    def parse_packer_detection(self):
        """Parse packer detection section."""
        packer = self.data.get("packer_detection", {})
        
        self.add_section("PACKER DETECTION")
        
        likely_packed = packer.get("likely_packed", False)
        if likely_packed:
            self.add_line(f"  Likely Packed: Yes [SUSPICIOUS - Packed binaries often hide malicious code]")
        else:
            self.add_line(f"  Likely Packed: No")
        
        packers = packer.get("packers_detected", [])
        if packers:
            self.add_subsection("Packers Detected [SUSPICIOUS]")
            for p in packers:
                self.add_line(f"    [SUSPICIOUS] {p.get('packer', 'Unknown')}")
        
        heuristics = packer.get("heuristic_indicators", [])
        if heuristics:
            self.add_subsection("Heuristic Indicators")
            for h in heuristics:
                self.add_line(f"    - {h}")
    
    def parse_entropy(self):
        """Parse entropy analysis section."""
        entropy = self.data.get("entropy", {})
        
        if not entropy:
            return
        
        self.add_section("ENTROPY ANALYSIS")
        
        file_entropy = entropy.get('file_entropy', 0)
        classification = entropy.get('entropy_classification', 'N/A')
        
        if file_entropy > 7.5:
            self.add_line(f"  File Entropy:    {file_entropy:.4f} [SUSPICIOUS - Very high entropy indicates packing/encryption]")
        else:
            self.add_line(f"  File Entropy:    {file_entropy:.4f}")
        self.add_line(f"  Classification:  {classification}")
        
        chunks = entropy.get("chunks", [])
        if chunks:
            self.add_subsection("Entropy by Chunk")
            for chunk in chunks:
                offset = chunk.get('offset', 'N/A')
                size = chunk.get('size', 'N/A')
                ent = chunk.get('entropy', 0)
                self.add_line(f"    Offset {offset}: Size {size}, Entropy {ent:.4f}")
    
    def parse_anti_analysis(self):
        """Parse anti-analysis techniques section."""
        anti = self.data.get("anti_analysis", {})
        
        if not anti:
            return
        
        self.add_section("ANTI-ANALYSIS TECHNIQUES")
        
        total = anti.get("total_techniques", 0)
        self.add_line(f"  Techniques Detected: {total}")
        
        techniques = anti.get("techniques_detected", [])
        if techniques:
            for tech in techniques:
                self.add_line(f"    [!] {tech}")
    
    def parse_language_detection(self):
        """Parse language detection section."""
        lang = self.data.get("language_detection", {})
        
        self.add_section("LANGUAGE DETECTION")
        
        languages = lang.get("languages", [])
        compilers = lang.get("compilers", [])
        confidence = lang.get("confidence", "N/A")
        
        if languages and languages != ["Unknown"]:
            self.add_line(f"  Languages: {', '.join(languages)}")
        else:
            self.add_line(f"  Languages: Unknown")
        
        if compilers and compilers != ["Unknown"]:
            self.add_line(f"  Compilers: {', '.join(compilers)}")
        else:
            self.add_line(f"  Compilers: Unknown")
        
        self.add_line(f"  Confidence: {confidence}")
    
    def parse_capability_mapping(self):
        """Parse capability mapping section."""
        cap = self.data.get("capability_mapping", {})
        
        if not cap:
            return
        
        self.add_section("CAPABILITY MAPPING (BEHAVIOR ANALYSIS)")
        
        behaviors = cap.get("detected_behaviors", [])
        total_sus = cap.get("total_suspicious_apis", 0)
        
        self.add_line(f"  Behaviors Detected: {len(behaviors)}")
        self.add_line(f"  Total Suspicious APIs: {total_sus}")
        
        if behaviors:
            self.add_subsection("Detected Behaviors")
            details = cap.get("behavior_details", {})
            confidence = cap.get("confidence_levels", {})
            
            for behavior in behaviors:
                conf = confidence.get(behavior, "unknown")
                self.add_line(f"    [{conf.upper()}] {behavior}")
                
                detail = details.get(behavior, {})
                apis = detail.get("apis", [])
                if apis:
                    self.add_line(f"            APIs: {', '.join(apis)}")
        
        risk = cap.get("risk_indicators", [])
        if risk:
            self.add_subsection("Risk Indicators")
            for r in risk:
                self.add_line(f"    [!] {r}")
        
        notes = cap.get("notes", [])
        if notes:
            self.add_subsection("Analysis Notes")
            for note in notes:
                self.add_line(f"    - {note}")
    
    def parse_yara_matches(self):
        """Parse YARA matches section."""
        yara = self.data.get("yara_matches", {})
        
        if not yara:
            return
        
        self.add_section("YARA MATCHES")
        
        matches = yara.get("matches", [])
        families = yara.get("malware_families", [])
        tags = yara.get("tags", [])
        
        if len(matches) > 0:
            self.add_line(f"  Total Matches: {len(matches)} [SUSPICIOUS - YARA rules matched!]")
        else:
            self.add_line(f"  Total Matches: {len(matches)}")
        
        if families:
            self.add_line(f"  Malware Families: [SUSPICIOUS] {', '.join(families)}")
        
        if tags:
            self.add_line(f"  Tags: {', '.join(tags)}")
        
        if matches:
            self.add_subsection("Match Details [SUSPICIOUS]")
            for match in matches:
                self.add_line(f"    [SUSPICIOUS] Rule: {match.get('rule', 'N/A')}")
                self.add_line(f"      Source: {match.get('source', 'N/A')}")
                self.add_line(f"      Strings Matched: {match.get('strings_matched', 0)}")
    
    def parse_authenticode(self):
        """Parse Authenticode signature section."""
        auth = self.data.get("authenticode", {})
        
        if not auth:
            return
        
        self.add_section("AUTHENTICODE SIGNATURE")
        
        is_signed = auth.get("is_signed", False)
        self.add_line(f"  Is Signed: {'Yes' if is_signed else 'No'}")
        
        if is_signed:
            sig_valid = auth.get('signature_valid')
            signer = auth.get('signer')
            
            # Clarify when signature isn't verified in static mode
            if sig_valid is None:
                self.add_line(f"  Signature Valid: Not verified in offline static mode")
            else:
                self.add_line(f"  Signature Valid: {'Yes' if sig_valid else 'No'}")
            
            if signer is None:
                self.add_line(f"  Signer: Not extracted (install osslsigncode for full analysis)")
            else:
                self.add_line(f"  Signer: {signer}")
            
            issuer = auth.get('issuer')
            if issuer:
                self.add_line(f"  Issuer: {issuer}")
            
            timestamp = auth.get('timestamp')
            if timestamp:
                self.add_line(f"  Timestamp: {timestamp}")
        
        self.add_line(f"  Verification Status: {auth.get('verification_status', 'N/A')}")
    
    def parse_import_categories(self):
        """Parse import categories section."""
        imp_cat = self.data.get("import_categories", {})
        
        if not imp_cat:
            return
        
        categories = imp_cat.get("categories", {})
        if not categories:
            return
        
        self.add_section("IMPORT CATEGORIZATION")
        
        self.add_line(f"  Total Categorized APIs: {imp_cat.get('total_categorized', 0)}")
        
        high_risk = imp_cat.get("high_risk_categories", [])
        if high_risk:
            self.add_line(f"  High Risk Categories: {', '.join(high_risk)}")
        
        self.add_subsection("Categories")
        for cat_name, cat_data in categories.items():
            count = cat_data.get("count", 0)
            if count > 0:
                imports = cat_data.get("imports", [])
                self.add_line(f"    {cat_name.upper()}: {count}")
                for imp in imports[:10]:
                    self.add_line(f"      - {imp}")
    
    def parse_entry_point_analysis(self):
        """Parse entry point analysis section."""
        ep = self.data.get("entry_point_analysis", {})
        
        if not ep:
            return
        
        self.add_section("ENTRY POINT ANALYSIS")
        
        self.add_line(f"  Entry Point RVA: {ep.get('entry_point_rva', 'N/A')}")
        self.add_line(f"  Entry Section:   {ep.get('entry_point_section', 'N/A')}")
        self.add_line(f"  First Bytes:     {ep.get('first_bytes', 'N/A')[:64]}...")
        
        suspicious = ep.get("suspicious_patterns", [])
        if suspicious:
            self.add_subsection("Suspicious Patterns")
            for s in suspicious:
                self.add_line(f"    [!] {s}")
        
        heuristics = ep.get("heuristics", [])
        if heuristics:
            self.add_subsection("Heuristics")
            for h in heuristics:
                self.add_line(f"    - {h}")
    
    def parse_config_detection(self):
        """Parse config detection section."""
        config = self.data.get("config_detection", {})
        
        if not config:
            return
        
        xor = config.get("xor_patterns", [])
        b64 = config.get("base64_blobs", [])
        high_ent = config.get("high_entropy_regions", [])
        
        if not xor and not b64 and not high_ent:
            return
        
        self.add_section("CONFIG/PAYLOAD DETECTION")
        
        if xor:
            self.add_subsection(f"XOR Patterns Detected: {len(xor)}")
            for x in xor[:10]:
                self.add_line(f"    Offset: {x.get('offset', 'N/A')}, Key: {x.get('key', 'N/A')}")
        
        if b64:
            self.add_subsection(f"Base64 Blobs Detected: {len(b64)}")
            for blob in b64[:10]:
                preview = blob.get('preview', 'N/A')[:50]
                self.add_line(f"    - {preview}...")
        
        if high_ent:
            self.add_subsection(f"High Entropy Regions: {len(high_ent)}")
            for region in high_ent[:10]:
                self.add_line(f"    Offset: {region.get('offset', 'N/A')}, Entropy: {region.get('entropy', 0):.4f}")
    
    def parse_instruction_anti_debug(self):
        """Parse instruction-level anti-debug section."""
        inst = self.data.get("instruction_anti_debug", {})
        
        if not inst:
            return
        
        # Check if skipped (non-PE file)
        if inst.get("skipped"):
            # Don't show this section at all for containers
            # It would just say "skipped" which is confusing
            return
        
        techniques = inst.get("techniques_found", [])
        if not techniques:
            return
        
        self.add_section("INSTRUCTION-LEVEL ANTI-DEBUG")
        
        for tech in techniques:
            self.add_line(f"    [!] {tech}")
        
        self.add_line("")
        self.add_line(f"  RDTSC Count:  {inst.get('rdtsc_count', 0)}")
        self.add_line(f"  CPUID Count:  {inst.get('cpuid_count', 0)}")
        self.add_line(f"  INT3 Count:   {inst.get('int3_count', 0)}")
        self.add_line(f"  INT2D Count:  {inst.get('int2d_count', 0)}")
        self.add_line(f"  SEH Manipulation: {'Yes' if inst.get('seh_manipulation', False) else 'No'}")
    
    def parse_threat_intel(self):
        """Parse threat intelligence section."""
        ti = self.data.get("threat_intel", {})
        
        if not ti:
            return
        
        self.add_section("THREAT INTELLIGENCE")
        
        # === VirusTotal Results ===
        vt = ti.get("virustotal", {})
        if vt and vt.get("status") == "found":
            self.add_subsection("VirusTotal Results")
            positives = vt.get("positives", 0)
            total = vt.get("total", 0)
            
            # Detection bar
            if total > 0:
                pct = int((positives / total) * 100)
                bar_len = 30
                filled = int((positives / total) * bar_len)
                bar = "█" * filled + "░" * (bar_len - filled)
                self.add_line(f"    Detections: {positives}/{total} ({pct}%)")
                self.add_line(f"    [{bar}]")
            
            threat_name = vt.get("popular_threat_name")
            if threat_name:
                self.add_line(f"    Threat Label: {threat_name}")
            
            malware_names = vt.get("malware_names", [])
            if malware_names:
                self.add_line(f"    AV Detections:")
                for name in malware_names[:5]:  # Show first 5
                    self.add_line(f"      - {name}")
            
            permalink = vt.get("permalink")
            if permalink:
                self.add_line(f"    VT Link: {permalink}")
        
        elif vt and vt.get("status") == "not_found":
            self.add_subsection("VirusTotal")
            self.add_line("    Status: Hash not found in VirusTotal database")
            self.add_line("    Note: Sample may be novel or previously unanalyzed")
        
        elif vt and vt.get("status") not in [None, "not_queried"]:
            self.add_subsection("VirusTotal")
            self.add_line(f"    Status: {vt.get('status')}")
        
        # === IOC Patterns ===
        iocs = ti.get("known_iocs", {})
        c2_urls = iocs.get("c2_urls", [])
        sus_ips = iocs.get("suspicious_ips", [])
        btc_addrs = iocs.get("bitcoin_addresses", [])
        
        if c2_urls:
            self.add_subsection("Potential C2 URLs")
            for url in c2_urls[:10]:
                self.add_line(f"    - {url}")
        
        if sus_ips:
            self.add_subsection("Suspicious IPs")
            for ip in sus_ips[:10]:
                self.add_line(f"    - {ip}")
        
        if btc_addrs:
            self.add_subsection("Bitcoin Addresses (Ransomware Indicator)")
            for addr in btc_addrs:
                self.add_line(f"    - {addr}")
    
    def parse_risk_score(self):
        """Parse risk score section (v3.0 hybrid scoring model)."""
        risk = self.data.get("risk_score", {})
        
        if not risk:
            return
        
        self.add_section("RISK ASSESSMENT")
        
        score = risk.get("score", 0)
        verdict = risk.get("verdict", "Unknown")
        scoring_model = risk.get("scoring_model", "unknown")
        context = risk.get("analysis_context", "")
        
        # Visual score bar with color coding
        bar_length = 40
        filled = int((score / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        # Verdict emoji
        verdict_emoji = {
            "Malicious": "🔴",
            "High Risk": "🟠", 
            "Suspicious": "🟡",
            "Medium Risk": "🟡",
            "Low Risk": "🟢",
            "Minimal Risk": "🟢",
            "Clean": "✅",
            "Unrated": "⚪",
            "Likely Clean": "✅"
        }.get(verdict, "❓")
        
        self.add_line(f"  Score: {score}/100")
        self.add_line(f"  [{bar}]")
        self.add_line(f"  Verdict: {verdict_emoji} {verdict}")
        
        if context:
            self.add_line(f"  Model: {scoring_model}")
        
        # === BASELINE INDICATORS (v3.0) ===
        baseline = risk.get("baseline_indicators", [])
        if baseline:
            self.add_subsection("Baseline Structural Indicators")
            for b in baseline:
                self.add_line(f"    ⚠ {b}")
        
        # === CONTRADICTIONS (Primary suspicion driver) ===
        contradictions = risk.get("contradictions", [])
        if contradictions:
            self.add_subsection("Contradictions Detected")
            for c in contradictions:
                self.add_line(f"    🚨 {c}")
        
        # === PATTERN DETECTIONS (Locker, Loader, etc.) ===
        indicators = risk.get("indicators", [])
        pattern_indicators = [i for i in indicators if "PATTERN" in i or "MALWARE" in i or "LOADER" in i]
        other_indicators = [i for i in indicators if i not in pattern_indicators]
        
        if pattern_indicators:
            self.add_subsection("Malware Pattern Detections")
            for ind in pattern_indicators:
                self.add_line(f"    🎯 {ind}")
        
        if other_indicators:
            self.add_subsection("Risk Indicators")
            for ind in other_indicators:
                self.add_line(f"    - {ind}")
        
        # === TRUST ADJUSTMENTS ===
        trust_adj = risk.get("trust_adjustments", [])
        if trust_adj:
            self.add_subsection("Trust Adjustments")
            for t in trust_adj:
                if "DISABLED" in t:
                    self.add_line(f"    ⚠ {t}")
                elif "-" in t:
                    self.add_line(f"    ✓ {t}")
                else:
                    self.add_line(f"    • {t}")
        
        # === SCORE BREAKDOWN ===
        breakdown = risk.get("breakdown", {})
        if breakdown:
            nonzero = {k: v for k, v in breakdown.items() if v != 0}
            if nonzero:
                self.add_subsection("Score Components")
                for key, value in nonzero.items():
                    sign = "+" if value > 0 else ""
                    self.add_line(f"    {key}: {sign}{value}")
    
    def parse_installer_info(self):
        """Parse installer detection info."""
        installer = self.data.get("installer_info", {})
        
        if not installer:
            return
        
        self.add_section("INSTALLER DETECTION")
        
        is_installer = installer.get("is_installer", False)
        
        if is_installer:
            framework = installer.get("framework", "Unknown")
            confidence = installer.get("confidence", 0)
            self.add_line(f"  ✓ DETECTED AS INSTALLER")
            self.add_line(f"  Framework:   {framework}")
            self.add_line(f"  Confidence:  {confidence:.0%}")
            
            evidence = installer.get("evidence", [])
            if evidence:
                self.add_subsection("Detection Evidence")
                for e in evidence:
                    self.add_line(f"    - {e}")
        else:
            self.add_line(f"  Not detected as installer")
    
    def parse_benign_indicators(self):
        """Parse benign indicators section."""
        benign = self.data.get("benign_indicators", {})
        
        if not benign:
            return
        
        score = benign.get("benign_score", 0)
        if score == 0:
            return
        
        self.add_section("BENIGN INDICATORS")
        
        self.add_line(f"  Benign Score: {score}")
        
        evidence = benign.get("evidence", [])
        if evidence:
            self.add_subsection("Evidence for Legitimacy")
            for e in evidence:
                self.add_line(f"    ✓ {e}")
        
        notes = benign.get("context_notes", [])
        if notes:
            self.add_subsection("Context Notes")
            for n in notes:
                self.add_line(f"    → {n}")
    
    def parse_why_suspicious(self):
        """Parse 'why suspicious' section (skip for benign verdicts)."""
        why = self.data.get("why_suspicious", {})
        
        if not why:
            return
        
        # Get verdict - skip this section entirely for benign verdicts
        verdict = self.data.get("risk_score", {}).get("verdict", "")
        is_benign = "Benign" in verdict or verdict == "Clean"
        
        # For benign files, only show if there are residual heuristics and retheme
        if is_benign:
            # Check if there's actually anything suspicious
            has_content = (
                why.get("suspicious_dlls") or 
                why.get("suspicious_apis") or 
                why.get("suspicious_behaviors") or 
                why.get("suspicious_characteristics")
            )
            if not has_content:
                return  # Skip section entirely
            
            # Use softer section title for benign files
            self.add_section("RESIDUAL HEURISTICS (Low Confidence)")
            self.add_line("  Note: File classified as benign - indicators below are informational only")
            self.add_line("")
        else:
            self.add_section("WHY IS THIS SUSPICIOUS?")
        
        # Suspicious DLLs
        sus_dlls = why.get("suspicious_dlls", [])
        if sus_dlls:
            self.add_subsection("DLL Imports" if is_benign else "Suspicious DLLs")
            for dll in sus_dlls:
                self.add_line(f"    [{dll.get('dll', 'N/A')}] ({dll.get('imported_functions', 0)} functions)")
                self.add_line(f"      Note: {dll.get('why_suspicious', 'N/A')}")
        
        # Suspicious APIs
        sus_apis = why.get("suspicious_apis", [])
        if sus_apis:
            self.add_subsection("API Imports" if is_benign else "Suspicious APIs")
            for api in sus_apis:
                self.add_line(f"    [{api.get('api', 'N/A')}] from {api.get('dll', 'N/A')}")
                self.add_line(f"      Note: {api.get('why_suspicious', 'N/A')}")
        
        # Suspicious Behaviors
        sus_behaviors = why.get("suspicious_behaviors", [])
        if sus_behaviors:
            self.add_subsection("Behaviors" if is_benign else "Suspicious Behaviors")
            for behavior in sus_behaviors:
                self.add_line(f"    [{behavior.get('behavior', 'N/A')}]")
                self.add_line(f"      Note: {behavior.get('why_suspicious', 'N/A')}")
                evidence = behavior.get('evidence_apis', [])
                if evidence:
                    self.add_line(f"      Evidence: {', '.join(evidence)}")
        
        # Suspicious Characteristics
        sus_chars = why.get("suspicious_characteristics", [])
        if sus_chars:
            self.add_subsection("Characteristics" if is_benign else "Suspicious Characteristics")
            for char in sus_chars:
                self.add_line(f"    [{char.get('characteristic', 'N/A')}]")
                self.add_line(f"      Note: {char.get('why_suspicious', 'N/A')}")
        
        # Analyst Notes
        notes = why.get("analyst_notes", [])
        if notes:
            self.add_subsection("Analyst Notes")
            for note in notes:
                self.add_line(f"    - {note}")
    
    def parse_hex_dump(self):
        """Parse hex dump section."""
        hex_dump = self.data.get("hex_dump", "")
        first_10 = self.data.get("first_10_hex", "")
        
        if not hex_dump:
            return
        
        self.add_section("HEX DUMP (First 256 bytes)")
        
        self.add_line(f"  Magic Bytes (First 10 hex): {first_10}")
        self.add_line("")
        
        for line in hex_dump.split("\n")[:16]:  # First 16 lines
            self.add_line(f"  {line}")
    
    def parse_footer(self):
        """Add report footer."""
        self.add_line("")
        self.add_line("=" * 80)
        self.add_line("                         END OF REPORT")
        self.add_line("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='Convert static analysis JSON to human-readable text',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 parser.py f40fd89b...json              # Auto-saves to {hash}_report.txt
  python3 parser.py results.json -o report.txt   # Saves to custom filename
  python3 parser.py results.json --stdout        # Prints to screen only
        '''
    )
    
    parser.add_argument('json_file', help='Path to static analysis JSON file')
    parser.add_argument('-o', '--output', help='Output text file path')
    parser.add_argument('--stdout', action='store_true', 
                       help='Print to screen instead of saving to file')
    
    args = parser.parse_args()
    
    # Read JSON file
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"Error: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Parse and convert
    parser_obj = StaticAnalysisParser(data)
    report = parser_obj.parse()
    
    # Output
    if args.stdout:
        # Print to screen only
        print(report)
    elif args.output:
        # Save to specified filename
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"Report saved to: {output_path}")
    else:
        # Default: auto-generate hash-based filename
        file_hash = data.get('hashes', {}).get('sha256', 'unknown')
        output_path = Path(f"{file_hash}_report.txt")
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
