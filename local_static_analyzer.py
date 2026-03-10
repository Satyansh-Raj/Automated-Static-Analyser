import os
import sys
import json
import time
import hashlib
import subprocess
import argparse
import logging
import binascii
import base64
from math import log2
from datetime import datetime
from pathlib import Path
import boto3
import magic
import pefile
import ssdeep
import yara
from typing import Dict, List, Any, Optional
import struct
import re
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('static_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
class AWSMalwareAnalyzer:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.ec2 = boto3.client('ec2', region_name=self.config['aws_region'])
        self.s3 = boto3.client('s3', region_name=self.config['aws_region'])
        self.analysis_results = {}
        self.instance_id = None
        self.instance_ip = None
    def load_config(self, config_file: str) -> Dict:
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Config file {config_file} not found")
            return self.get_default_config()
    def get_default_config(self) -> Dict:
        return {
            "aws_region": "us-east-1",
            "instance_type": "t3.medium",
            "ami_id": "ami-04614d1876ac7381b",
            "security_group_id": "sg-malware-analysis",
            "subnet_id": "",
            "s3_bucket": "malware-analysis-results",
            "output_format": "json",
            "analysis_timeout": 3600
        }
class StaticAnalyzer:
    INSTALLER_WHITELIST_URLS = [
        "nsis.sf.net", "nullsoft.com", "installshield.com", "innosetup.com",
        "microsoft.com", "windows.com", "visualstudio.com", "adobe.com",
        "python.org", "java.com", "oracle.com", "google.com", "mozilla.org",
        "steampowered.com", "steamcommunity.com", "epicgames.com", "unity.com"
    ]
    STANDARD_SECTIONS = ['.text', '.data', '.rdata', '.bss', '.idata', '.edata',
                         '.rsrc', '.reloc', '.pdata', '.tls', '.CRT', 'CODE', 'DATA']
    BEHAVIOR_EXPECTATIONS = {
        "installer": {
            "expected": [
                "high_entropy", "overlay", "packer", "registry_activity",
                "dll_loading", "file_writes", "large_size", "upx", "nsis",
                "compressed_sections", "resource_heavy"
            ],
            "suspicious": [
                "process_injection", "credential_theft", "keylogging",
                "browser_hooking", "crypto_mining"
            ],
            "contradictions": [
                "no_version_info_and_unsigned", "injects_into_system_process",
                "tiny_size_with_network"
            ]
        },
        "application": {
            "expected": [
                "dll_loading", "registry_reads", "file_reads", "network_optional"
            ],
            "suspicious": [
                "process_injection", "high_entropy", "overlay", "packer",
                "keylogging", "credential_theft"
            ],
            "contradictions": [
                "gui_app_no_ui_imports", "claims_utility_has_injection"
            ]
        },
        "library": {
            "expected": [
                "dll_loading", "exports", "no_entry_point"
            ],
            "suspicious": [
                "network", "file_writes", "registry_persistence"
            ],
            "contradictions": []
        },
        "loader_dropper": {
            "expected": [],
            "suspicious": [
                "network", "file_writes", "process_creation", "high_entropy",
                "small_code_large_data"
            ],
            "contradictions": []
        },
        "unknown": {
            "expected": ["dll_loading", "registry_reads"],
            "suspicious": ["process_injection", "credential_theft"],
            "contradictions": []
        }
    }
    def __init__(self, malware_path: str, config: Dict = None):
        self.malware_path = Path(malware_path)
        self.config = config or {}
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "file_path": str(self.malware_path),
            "metadata": {},
            "hashes": {},
            "strings": {},
            "pe_analysis": {},
            "imports_exports": {},
            "packer_detection": {},
            "hex_dump": "",
            "entropy": {},
            "resources": {},
            "anti_analysis": {},
            "language_detection": {},
            "rich_header": {},
            "pdb_info": {},
            "tls_callbacks": {},
            "overlay": {},
            "version_info": {},
            "capability_mapping": {},
            "yara_matches": {},
            "authenticode": {},
            "import_categories": {},
            "entry_point_analysis": {},
            "config_detection": {},
            "instruction_anti_debug": {},
            "threat_intel": {},
            "installer_info": {},
            "benign_indicators": {},
            "file_role": {},
            "risk_score": {}
        }
    def analyze_all(self) -> Dict:
        logger.info(f"Starting static analysis of {self.malware_path}")
        self.get_file_metadata()
        self.calculate_hashes()
        self.extract_strings()
        if self.is_pe_file():
            self.analyze_pe_file()
            self.analyze_imports_exports()
            self.calculate_imphash()
            self.analyze_resources()
            self.analyze_rich_header()
            self.extract_pdb_path()
            self.enumerate_tls_callbacks()
            self.analyze_overlay()
            self.analyze_version_info()
            self.map_capabilities()
            self.categorize_imports_by_behavior()
            self.analyze_entry_point()
            self.analyze_authenticode()
        self.detect_packers()
        self.get_hex_dump()
        self.calculate_entropy()
        self.detect_anti_analysis()
        self.detect_programming_language()
        self.scan_yara_rules()
        self.detect_config_blobs()
        self.detect_instruction_anti_debug()
        self.correlate_threat_intel()
        self.detect_installer_framework()
        self.classify_file_role()
        self.analyze_api_clusters()
        self.calculate_benign_indicators()
        self.detect_malware_indicators()
        self.detect_contradictions()
        self.calculate_risk_score()
        self.generate_suspicion_report()
        return self.results
    def get_file_metadata(self):
        try:
            stat_info = os.stat(self.malware_path)
            file_magic = magic.from_file(str(self.malware_path))
            mime_type = magic.from_file(str(self.malware_path), mime=True)
            self.results["metadata"] = {
                "filename": self.malware_path.name,
                "file_size": stat_info.st_size,
                "file_size_human": self.human_readable_size(stat_info.st_size),
                "file_type": file_magic,
                "mime_type": mime_type,
                "creation_time": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                "modification_time": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "access_time": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                "permissions": oct(stat_info.st_mode)[-3:]
            }
            logger.info(f"File metadata extracted: {self.results['metadata']['file_type']}")
        except Exception as e:
            logger.error(f"Error extracting file metadata: {e}")
    def calculate_hashes(self):
        try:
            with open(self.malware_path, 'rb') as f:
                file_data = f.read()
            self.results["hashes"] = {
                "md5": hashlib.md5(file_data).hexdigest(),
                "sha1": hashlib.sha1(file_data).hexdigest(),
                "sha256": hashlib.sha256(file_data).hexdigest(),
                "sha512": hashlib.sha512(file_data).hexdigest(),
                "sha3_256": hashlib.sha3_256(file_data).hexdigest(),
                "blake2b": hashlib.blake2b(file_data).hexdigest(),
                "ssdeep": ssdeep.hash(file_data),
                "crc32": format(binascii.crc32(file_data) & 0xffffffff, '08x')
            }
            logger.info(f"Hashes calculated - SHA256: {self.results['hashes']['sha256']}")
        except Exception as e:
            logger.error(f"Error calculating hashes: {e}")
    def extract_strings(self):
        try:
            ascii_strings = self.extract_ascii_strings()
            unicode_strings = self.extract_unicode_strings()
            categorized = self.categorize_strings(ascii_strings + unicode_strings)
            self.results["strings"] = {
                "total_strings": len(ascii_strings) + len(unicode_strings),
                "ascii_strings": len(ascii_strings),
                "unicode_strings": len(unicode_strings),
                "interesting_strings": categorized["interesting"],
                "urls": categorized["urls"],
                "ip_addresses": categorized["ips"],
                "registry_keys": categorized["registry"],
                "file_paths": categorized["paths"],
                "emails": categorized["emails"],
                "crypto_payment": categorized["crypto_payment"],
                "crypto_primitives": categorized["crypto_primitives"],
                "api_calls": categorized["api_calls"],
                "dll_references": categorized["dlls"],
                "context_keywords": categorized["context_keywords"]
            }
            logger.info(f"Extracted {self.results['strings']['total_strings']} strings")
        except Exception as e:
            logger.error(f"Error extracting strings: {e}")
    def extract_ascii_strings(self, min_length: int = 4) -> List[str]:
        strings = []
        try:
            with open(self.malware_path, 'rb') as f:
                data = f.read()
            ascii_regex = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
            strings = [s.decode('ascii') for s in ascii_regex.findall(data)]
        except Exception as e:
            logger.error(f"Error extracting ASCII strings: {e}")
        return strings[:1000]
    def extract_unicode_strings(self, min_length: int = 4) -> List[str]:
        strings = []
        try:
            with open(self.malware_path, 'rb') as f:
                data = f.read()
            unicode_regex = re.compile(b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}')
            unicode_matches = unicode_regex.findall(data)
            for match in unicode_matches:
                try:
                    decoded = match.decode('utf-16le', errors='ignore').strip('\x00')
                    if decoded:
                        strings.append(decoded)
                except:
                    pass
        except Exception as e:
            logger.error(f"Error extracting Unicode strings: {e}")
        return strings[:500]
    def categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        categories = {
            "interesting": [],
            "urls": [],
            "ips": [],
            "registry": [],
            "paths": [],
            "emails": [],
            "crypto_payment": [],
            "crypto_primitives": [],
            "api_calls": [],
            "dlls": [],
            "whitelisted_urls": [],
            "context_keywords": []
        }
        url_pattern = re.compile(r'https?://[^\s]+')
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        registry_pattern = re.compile(r'(\\\\Run\\b|\\\\RunOnce\\b|\\\\Services\\\\|\\\\Winlogon|\\\\CurrentVersion\\\\Policies|\\\\Tasks\\\\|Startup\\\\)')
        path_pattern = re.compile(r'([A-Z]:\\|\\\\|\/)[\\\w\\\s\\\\\./-]+')
        dll_pattern = re.compile(r'\w+\.dll', re.IGNORECASE)
        xml_context_patterns = ['version=', 'encoding=', '<?xml', 'xmlns', 'assembly']
        shell_extension_patterns = [
            'ShellEx', 'PropertySheetHandlers', 'ContextMenuHandlers',
            'IconHandler', 'CopyHookHandlers', 'DragDropHandlers'
        ]
        context_aware_keywords = {
            "payload": {"installer": "benign", "tool": "context", "unknown": "context"},
            "admin": {"installer": "benign", "tool": "benign", "application": "benign", "unknown": "context"},
            "root": {"installer": "context", "tool": "context", "unknown": "context"},
            "install": {"installer": "benign", "tool": "benign", "unknown": "benign"},
            "setup": {"installer": "benign", "tool": "benign", "unknown": "benign"},
            "uninstall": {"installer": "benign", "tool": "benign", "unknown": "benign"},
        }
        suspicious_keywords = [
            'ransom', 'exploit', 'backdoor', 'keylog', 'steal',
            'inject', 'hook', 'c2', 'beacon', 'shellcode'
        ]
        api_keywords = [
            'CreateProcess', 'VirtualAlloc', 'WriteProcessMemory',
            'SetWindowsHook', 'GetProcAddress', 'LoadLibrary',
            'RegSetValue', 'InternetOpen', 'HttpSendRequest',
            'CreateRemoteThread', 'OpenProcess', 'ReadProcessMemory'
        ]
        crypto_payment_indicators = [
            'bitcoin', 'btc', 'wallet', 'monero', 'xmr', 'ethereum', 'eth',
            'ransom', 'decrypt your', 'pay to', 'your files', 'encrypted',
            'cryptocurrency', 'payment', 'tor browser', '.onion'
        ]
        crypto_primitive_keywords = [
            'md5', 'sha1', 'sha256', 'sha512', 'aes', 'rsa', 'hmac',
            'crypt', 'cipher', 'hash', 'digest', 'pkcs', 'x509'
        ]
        for string in strings:
            string_lower = string.lower()
            if any(sep in string for sep in shell_extension_patterns):
                continue
            url_match = url_pattern.search(string)
            if url_match:
                url = url_match.group()
                is_whitelisted = any(domain in url.lower() for domain in self.INSTALLER_WHITELIST_URLS)
                if is_whitelisted:
                    categories["whitelisted_urls"].append(string)
                else:
                    categories["urls"].append(string)
            ip_match = ip_pattern.search(string)
            if ip_match:
                ip = ip_match.group()
                octets = ip.split('.')
                is_version = all(int(o) < 10 for o in octets if o.isdigit())
                is_xml_context = any(ctx in string_lower for ctx in xml_context_patterns)
                is_benign_ip = ip in ['0.0.0.0', '127.0.0.1', '255.255.255.255']
                if not is_version and not is_xml_context and not is_benign_ip:
                    categories["ips"].append(string)
            if email_pattern.search(string):
                categories["emails"].append(string)
            if registry_pattern.search(string):
                categories["registry"].append(string)
            if path_pattern.search(string):
                categories["paths"].append(string)
            if dll_pattern.search(string):
                categories["dlls"].append(string)
            for api in api_keywords:
                if api.lower() in string_lower:
                    categories["api_calls"].append(string)
                    break
            if any(crypto in string_lower for crypto in crypto_payment_indicators):
                categories["crypto_payment"].append(string)
            elif any(prim in string_lower for prim in crypto_primitive_keywords):
                categories["crypto_primitives"].append(string)
            for keyword in context_aware_keywords:
                if keyword in string_lower:
                    categories["context_keywords"].append({
                        "keyword": keyword,
                        "string": string,
                        "interpretation_map": context_aware_keywords[keyword]
                    })
                    break
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    categories["interesting"].append(string)
                    break
        for key in categories:
            if key != "context_keywords":
                categories[key] = list(set(categories[key]))[:50]
            else:
                seen = set()
                unique = []
                for item in categories[key]:
                    if item["string"] not in seen:
                        seen.add(item["string"])
                        unique.append(item)
                categories[key] = unique[:50]
        return categories
    def is_pe_file(self) -> bool:
        try:
            with open(self.malware_path, 'rb') as f:
                header = f.read(2)
                return header == b'MZ'
        except:
            return False
    def analyze_pe_file(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            self.results["pe_analysis"]["header"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "time_date_stamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "optional_header_magic": hex(pe.OPTIONAL_HEADER.Magic),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
                "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "checksum": hex(pe.OPTIONAL_HEADER.CheckSum)
            }
            sections = []
            for section in pe.sections:
                section_data = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy(),
                    "characteristics": hex(section.Characteristics),
                    "md5": section.get_hash_md5(),
                    "suspicious": self.is_section_suspicious(section)
                }
                sections.append(section_data)
            self.results["pe_analysis"]["sections"] = sections
            anomalies = []
            is_installer = self.results.get("installer_info", {}).get("is_installer", False)
            suspicious_sections = ['.upx', '.aspack', '.adata', '.mpress', '.petite', '.yoda']
            standard_sections = ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.pdata', '.idata', '.edata']
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                if any(sus in section_name for sus in suspicious_sections):
                    anomalies.append(f"Packer section detected: {section_name}")
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                if entropy > 7.0:
                    if is_installer and section_name.lower() in ['.rsrc', '.data', '.rdata']:
                        pass
                    else:
                        anomalies.append(f"High entropy section: {section_name} ({entropy:.2f})")
            if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
                anomalies.append("No entry point defined")
            actual_checksum = pe.generate_checksum()
            if pe.OPTIONAL_HEADER.CheckSum != actual_checksum:
                anomalies.append("Invalid PE checksum")
            self.results["pe_analysis"]["anomalies"] = anomalies
            pe.close()
            logger.info("PE analysis completed")
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
            self.results["pe_analysis"]["error"] = str(e)
    def is_section_suspicious(self, section) -> bool:
        suspicious_indicators = []
        if section.get_entropy() > 7.0:
            suspicious_indicators.append("high_entropy")
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_WRITE = 0x80000000
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE and
            section.Characteristics & IMAGE_SCN_MEM_WRITE):
            suspicious_indicators.append("rwx_permissions")
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            suspicious_indicators.append("size_anomaly")
        return len(suspicious_indicators) > 0
    def analyze_imports_exports(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            imports = {}
            suspicious_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            functions.append({
                                "name": func_name,
                                "address": hex(imp.address),
                                "ordinal": imp.ordinal
                            })
                            suspicious_apis = [
                                'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                                'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState',
                                'InternetOpenUrl', 'URLDownloadToFile', 'WinExec',
                                'ShellExecute', 'CreateProcess', 'RegSetValue'
                            ]
                            if func_name in suspicious_apis:
                                suspicious_imports.append(f"{dll_name}!{func_name}")
                    imports[dll_name] = functions
            self.results["imports_exports"]["imports"] = imports
            self.results["imports_exports"]["suspicious_imports"] = suspicious_imports
            self.results["imports_exports"]["total_imports"] = sum(len(funcs) for funcs in imports.values())
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append({
                            "name": exp.name.decode('utf-8', errors='ignore'),
                            "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                            "ordinal": exp.ordinal
                        })
            self.results["imports_exports"]["exports"] = exports
            self.results["imports_exports"]["total_exports"] = len(exports)
            pe.close()
            logger.info(f"Import/Export analysis completed - {len(imports)} DLLs imported")
        except Exception as e:
            logger.error(f"Error analyzing imports/exports: {e}")
    def calculate_imphash(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            imphash = pe.get_imphash()
            self.results["pe_analysis"]["imphash"] = imphash
            pe.close()
            logger.info(f"Imphash calculated: {imphash}")
        except Exception as e:
            logger.error(f"Error calculating imphash: {e}")
            self.results["pe_analysis"]["imphash"] = "N/A"
    def analyze_resources(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "Unknown")
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                     resource_lang.data.struct.Size)
                                    resource_info = {
                                        "type": name,
                                        "id": resource_id.struct.Id if hasattr(resource_id.struct, 'Id') else "N/A",
                                        "language": resource_lang.struct.Id if hasattr(resource_lang.struct, 'Id') else "N/A",
                                        "size": resource_lang.data.struct.Size,
                                        "offset": hex(resource_lang.data.struct.OffsetToData),
                                        "md5": hashlib.md5(data).hexdigest(),
                                        "entropy": self.calculate_data_entropy(data)
                                    }
                                    resources.append(resource_info)
            self.results["resources"] = {
                "total_resources": len(resources),
                "resources_list": resources[:20]
            }
            pe.close()
            logger.info(f"Resource analysis completed - {len(resources)} resources found")
        except Exception as e:
            logger.error(f"Error analyzing resources: {e}")
    def detect_packers(self):
        try:
            packer_rules = """
            rule UPX_Packer {
                strings:
                    $upx1 = "UPX!"
                    $upx2 = "UPX0"
                    $upx3 = "UPX1"
                condition:
                    any of them
            }
            rule ASPack_Packer {
                strings:
                    $aspack = "ASPack"
                condition:
                    $aspack
            }
            rule VMProtect {
                strings:
                    $vmp1 = ".vmp0"
                    $vmp2 = ".vmp1"
                    $vmp3 = "VMProtect"
                condition:
                    any of them
            }
            rule Themida {
                strings:
                    $themida1 = "Themida"
                    $themida2 = ".themida"
                condition:
                    any of them
            }
            rule PECompact {
                strings:
                    $pec1 = "PECompact"
                    $pec2 = "PEC2"
                condition:
                    any of them
            }
            """
            rules = yara.compile(source=packer_rules)
            matches = rules.match(str(self.malware_path))
            packers_detected = []
            for match in matches:
                packers_detected.append({
                    "packer": match.rule,
                    "strings_matched": [str(s) for s in match.strings]
                })
            heuristics = []
            if self.is_pe_file():
                try:
                    pe = pefile.PE(str(self.malware_path))
                    for section in pe.sections:
                        if pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress and                           pe.OPTIONAL_HEADER.AddressOfEntryPoint < (section.VirtualAddress + section.Misc_VirtualSize):
                            if section.get_entropy() > 7.0:
                                heuristics.append("High entropy in entry point section")
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        import_count = sum(1 for _ in pe.DIRECTORY_ENTRY_IMPORT)
                        if import_count < 3:
                            heuristics.append("Suspiciously low import count")
                    pe.close()
                except:
                    pass
            self.results["packer_detection"] = {
                "packers_detected": packers_detected,
                "heuristic_indicators": heuristics,
                "likely_packed": len(packers_detected) > 0 or len(heuristics) > 0
            }
            logger.info(f"Packer detection completed - {len(packers_detected)} packers detected")
        except Exception as e:
            logger.error(f"Error detecting packers: {e}")
    def get_hex_dump(self, num_bytes: int = 256):
        try:
            with open(self.malware_path, 'rb') as f:
                data = f.read(num_bytes)
            hex_dump = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                hex_dump.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
            self.results["hex_dump"] = '\n'.join(hex_dump)
            first_10_hex = ''.join(f'{b:02x}' for b in data[:5])
            self.results["first_10_hex"] = first_10_hex
            logger.info("Hex dump generated")
        except Exception as e:
            logger.error(f"Error generating hex dump: {e}")
    def calculate_entropy(self):
        try:
            with open(self.malware_path, 'rb') as f:
                data = f.read()
            file_entropy = self.calculate_data_entropy(data)
            self.results["entropy"] = {
                "file_entropy": file_entropy,
                "entropy_classification": self.classify_entropy(file_entropy)
            }
            chunk_size = len(data) // 4 if len(data) > 4 else len(data)
            chunks_entropy = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                if chunk:
                    chunks_entropy.append({
                        "offset": hex(i),
                        "size": len(chunk),
                        "entropy": self.calculate_data_entropy(chunk)
                    })
            self.results["entropy"]["chunks"] = chunks_entropy
            logger.info(f"Entropy calculated: {file_entropy:.4f}")
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
    def calculate_data_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        entropy = 0.0
        data_len = len(data)
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability and log2(probability))
        return entropy
    def classify_entropy(self, entropy: float) -> str:
        is_installer = self.results.get("installer_info", {}).get("is_installer", False)
        is_container = not self.is_pe_file()
        if entropy < 1:
            return "Very Low (Likely empty or padding)"
        elif entropy < 4:
            return "Low (Likely text or simple data)"
        elif entropy < 6:
            return "Medium (Normal executable)"
        elif entropy < 7:
            if is_installer or is_container:
                return "High (Compressed payload - normal for installers)"
            return "High (Possibly compressed)"
        elif entropy < 7.5:
            if is_installer or is_container:
                return "Very High (CAB/compressed content - expected)"
            return "Very High (Likely packed or compressed)"
        else:
            if is_installer or is_container:
                return "Extremely High (Heavy compression - expected for large installers)"
            return "Extremely High (Possibly packed/encrypted)"
    def detect_anti_analysis(self):
        try:
            anti_techniques = []
            is_container = not self.is_pe_file()
            with open(self.malware_path, 'rb') as f:
                content = f.read()
            content_str = str(content)
            if not is_container:
                anti_debug_strings = [
                    b'IsDebuggerPresent',
                    b'CheckRemoteDebuggerPresent',
                    b'NtQueryInformationProcess',
                    b'OutputDebugString',
                    b'ZwQueryInformationProcess',
                    b'NtSetInformationThread',
                    b'DebugActiveProcess'
                ]
                for pattern in anti_debug_strings:
                    if pattern in content:
                        anti_techniques.append(f"Anti-debugging: {pattern.decode('utf-8', errors='ignore')}")
            if not is_container:
                anti_vm_strings = [
                    b'VMware',
                    b'VirtualBox',
                    b'Virtual Machine',
                    b'QEMU',
                    b'Xen',
                    b'vbox',
                    b'vmware',
                    b'qemu-ga',
                    b'virtualbox',
                    b'VM Additions',
                    b'Hyper-V'
                ]
                for pattern in anti_vm_strings:
                    if pattern in content:
                        anti_techniques.append(f"Anti-VM: {pattern.decode('utf-8', errors='ignore')}")
            anti_sandbox = [
                b'SbieDll.dll',
                b'SandboxieControlWndClass',
                b'Sandboxie',
                b'CWSandbox',
                b'Anubis'
            ]
            for pattern in anti_sandbox:
                if pattern in content:
                    anti_techniques.append(f"Anti-sandbox: {pattern.decode('utf-8', errors='ignore')}")
            if not is_container:
                process_detection = [
                    b'wireshark',
                    b'fiddler',
                    b'processhacker',
                    b'procmon',
                    b'procexp',
                    b'ida',
                    b'ollydbg',
                    b'x64dbg',
                    b'windbg'
                ]
                for pattern in process_detection:
                    if pattern in content:
                        anti_techniques.append(f"Tool detection: {pattern.decode('utf-8', errors='ignore')}")
            if not is_container:
                timing_checks = [
                    b'GetTickCount',
                    b'QueryPerformanceCounter',
                    b'rdtsc',
                    b'GetSystemTime',
                    b'NtQuerySystemTime'
                ]
                for pattern in timing_checks:
                    if pattern in content:
                        anti_techniques.append(f"Timing check: {pattern.decode('utf-8', errors='ignore')}")
            result = {
                "techniques_detected": list(set(anti_techniques)),
                "total_techniques": len(set(anti_techniques))
            }
            if is_container:
                result["note"] = "Limited analysis for container files - VM/tool strings may be metadata, not evasion"
            self.results["anti_analysis"] = result
            logger.info(f"Anti-analysis detection completed - {len(anti_techniques)} techniques found")
        except Exception as e:
            logger.error(f"Error detecting anti-analysis techniques: {e}")
    def detect_programming_language(self):
        try:
            if not self.is_pe_file():
                self.results["language_detection"] = {
                    "languages": ["N/A (Container file)"],
                    "compilers": ["N/A"],
                    "confidence": "N/A",
                    "note": "Language detection applies to extracted PE payloads, not container files"
                }
                logger.info("Language detection skipped: not a PE file")
                return
            languages_detected = []
            compilers_detected = []
            with open(self.malware_path, 'rb') as f:
                content = f.read()
            if b'mscoree.dll' in content or b'mscorlib' in content:
                languages_detected.append(".NET (C#/VB.NET)")
            if b'Borland' in content or b'Delphi' in content:
                languages_detected.append("Delphi")
                compilers_detected.append("Borland Delphi")
            if b'MSVCRT' in content or b'Visual C++' in content:
                languages_detected.append("C/C++")
                compilers_detected.append("MSVC")
            if b'mingw' in content.lower() or b'gcc' in content.lower():
                languages_detected.append("C/C++")
                compilers_detected.append("MinGW/GCC")
            if b'python' in content.lower() or b'pyinstaller' in content.lower():
                languages_detected.append("Python")
                if b'pyinstaller' in content.lower():
                    compilers_detected.append("PyInstaller")
            if b'AutoIt' in content or b'Aut2Exe' in content:
                languages_detected.append("AutoIt")
                compilers_detected.append("Aut2Exe")
            if b'Go build' in content or b'runtime/cgo' in content:
                languages_detected.append("Go")
                compilers_detected.append("Go compiler")
            if b'.rustc' in content or b'rust_begin_unwind' in content:
                languages_detected.append("Rust")
                compilers_detected.append("rustc")
            rich = self.results.get("rich_header", {})
            if rich.get("present"):
                toolchain = rich.get("toolchain_info", [])
                for tool in toolchain:
                    if "Visual Studio" in str(tool) or "MSVC" in str(tool):
                        if "C/C++" not in languages_detected:
                            languages_detected.append("C/C++")
                        if "MSVC" not in compilers_detected:
                            compilers_detected.append("MSVC")
            self.results["language_detection"] = {
                "languages": list(set(languages_detected)) if languages_detected else ["Unknown"],
                "compilers": list(set(compilers_detected)) if compilers_detected else ["Unknown"],
                "confidence": "High" if languages_detected else "Low"
            }
            logger.info(f"Language detection completed: {languages_detected}")
        except Exception as e:
            logger.error(f"Error detecting programming language: {e}")
    def analyze_rich_header(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            rich_header_info = {
                "present": False,
                "entries": [],
                "rich_hash": None,
                "toolchain_info": []
            }
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER:
                rich_header_info["present"] = True
                rich_data = pe.get_data(0x80, 0x80)
                if rich_data:
                    rich_header_info["rich_hash"] = hashlib.md5(rich_data).hexdigest()
                if hasattr(pe.RICH_HEADER, 'values'):
                    for entry in pe.RICH_HEADER.values:
                        if isinstance(entry, tuple) and len(entry) >= 2:
                            comp_id, count = entry[0], entry[1]
                            tool_id = (comp_id >> 16) & 0xFFFF
                            build_ver = comp_id & 0xFFFF
                            tool_info = self._identify_rich_tool(tool_id, build_ver)
                            rich_header_info["entries"].append({
                                "tool_id": tool_id,
                                "build_version": build_ver,
                                "count": count,
                                "tool_name": tool_info
                            })
                            if tool_info not in rich_header_info["toolchain_info"]:
                                rich_header_info["toolchain_info"].append(tool_info)
            pe.close()
            self.results["rich_header"] = rich_header_info
            logger.info(f"Rich Header analysis completed: {'Present' if rich_header_info['present'] else 'Not found'}")
        except Exception as e:
            logger.error(f"Error analyzing Rich Header: {e}")
            self.results["rich_header"] = {"error": str(e)}
    def _identify_rich_tool(self, tool_id: int, build_ver: int) -> str:
        tool_map = {
            0: "Unknown",
            1: "Import Table",
            2: "Linker",
            3: "CVTRES",
            4: "Linker (old)",
            5: "MASM",
            6: "C Compiler",
            7: "C++ Compiler",
            8: "ASM",
            9: "Resource Compiler",
            10: "Export Table",
            11: "Total",
            14: "MASM (ML64)",
            15: "C++ Compiler (CL)",
            147: "VS2017",
            257: "VS2019",
            259: "VS2022"
        }
        tool_name = tool_map.get(tool_id, f"Tool_{tool_id}")
        return f"{tool_name} (Build {build_ver})"
    def extract_pdb_path(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            pdb_info = {
                "pdb_path": None,
                "pdb_filename": None,
                "potential_username": None,
                "potential_project": None,
                "guid": None,
                "age": None
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                    if debug_entry.struct.Type == 2:
                        debug_data = pe.get_data(debug_entry.struct.PointerToRawData,
                                                debug_entry.struct.SizeOfData)
                        if debug_data[:4] == b'RSDS':
                            guid_bytes = debug_data[4:20]
                            pdb_info["guid"] = guid_bytes.hex()
                            age = struct.unpack('<I', debug_data[20:24])[0]
                            pdb_info["age"] = age
                            pdb_path = debug_data[24:].split(b'\x00')[0].decode('utf-8', errors='ignore')
                            pdb_info["pdb_path"] = pdb_path
                            pdb_info["pdb_filename"] = os.path.basename(pdb_path)
                            path_parts = pdb_path.replace('\\', '/').split('/')
                            for i, part in enumerate(path_parts):
                                if part.lower() == 'users' and i + 1 < len(path_parts):
                                    pdb_info["potential_username"] = path_parts[i + 1]
                                if part.lower() in ['projects', 'source', 'src', 'repos']:
                                    if i + 1 < len(path_parts):
                                        pdb_info["potential_project"] = path_parts[i + 1]
                        elif debug_data[:4] == b'NB10':
                            pdb_path = debug_data[16:].split(b'\x00')[0].decode('utf-8', errors='ignore')
                            pdb_info["pdb_path"] = pdb_path
                            pdb_info["pdb_filename"] = os.path.basename(pdb_path)
            pe.close()
            self.results["pdb_info"] = pdb_info
            logger.info(f"PDB path extraction completed: {pdb_info.get('pdb_path', 'Not found')}")
        except Exception as e:
            logger.error(f"Error extracting PDB path: {e}")
            self.results["pdb_info"] = {"error": str(e)}
    def enumerate_tls_callbacks(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            tls_info = {
                "has_tls": False,
                "callbacks": [],
                "pre_entry_execution": False,
                "tls_directory": {},
                "parsing_status": "not_applicable",
                "analysis_note": None
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls = pe.DIRECTORY_ENTRY_TLS
                tls_info["has_tls"] = True
                tls_info["tls_directory"] = {
                    "start_address_of_raw_data": hex(tls.struct.StartAddressOfRawData),
                    "end_address_of_raw_data": hex(tls.struct.EndAddressOfRawData),
                    "address_of_index": hex(tls.struct.AddressOfIndex),
                    "address_of_callbacks": hex(tls.struct.AddressOfCallBacks),
                    "size_of_zero_fill": tls.struct.SizeOfZeroFill,
                    "characteristics": hex(tls.struct.Characteristics)
                }
                callback_rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                parsing_success = False
                try:
                    callback_count = 0
                    max_callbacks = 20
                    while callback_count < max_callbacks:
                        if pe.OPTIONAL_HEADER.Magic == 0x10b:
                            callback_addr = struct.unpack('<I', pe.get_data(callback_rva, 4))[0]
                            callback_rva += 4
                        else:
                            callback_addr = struct.unpack('<Q', pe.get_data(callback_rva, 8))[0]
                            callback_rva += 8
                        if callback_addr == 0:
                            parsing_success = True
                            break
                        tls_info["callbacks"].append({
                            "address": hex(callback_addr),
                            "rva": hex(callback_addr - pe.OPTIONAL_HEADER.ImageBase)
                        })
                        callback_count += 1
                    if callback_count >= max_callbacks:
                        tls_info["parsing_status"] = "truncated"
                    else:
                        tls_info["parsing_status"] = "success"
                except Exception as parse_error:
                    tls_info["parsing_status"] = "failed"
                    tls_info["analysis_note"] = f"Callback parsing failed: {str(parse_error)}"
                if len(tls_info["callbacks"]) > 0:
                    tls_info["pre_entry_execution"] = True
                    tls_info["analysis_note"] = (
                        f"Found {len(tls_info['callbacks'])} TLS callback(s) that execute before entry point. "
                        "This is suspicious as malware may use TLS to run code before debuggers attach."
                    )
                else:
                    tls_info["pre_entry_execution"] = False
                    tls_info["analysis_note"] = (
                        "TLS directory present but no callbacks registered. "
                        "This is common in Delphi and some C++ runtime libraries (not suspicious)."
                    )
            pe.close()
            self.results["tls_callbacks"] = tls_info
            logger.info(f"TLS callback enumeration completed: {len(tls_info['callbacks'])} callbacks found")
        except Exception as e:
            logger.error(f"Error enumerating TLS callbacks: {e}")
            self.results["tls_callbacks"] = {"error": str(e)}
    def analyze_overlay(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            file_size = os.path.getsize(self.malware_path)
            overlay_info = {
                "has_overlay": False,
                "overlay_offset": 0,
                "overlay_size": 0,
                "overlay_entropy": 0.0,
                "overlay_ratio": 0.0,
                "suspicious": False,
                "magic_bytes": None,
                "possible_content": None
            }
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset and overlay_offset < file_size:
                overlay_size = file_size - overlay_offset
                if overlay_size > 0:
                    overlay_info["has_overlay"] = True
                    overlay_info["overlay_offset"] = overlay_offset
                    overlay_info["overlay_size"] = overlay_size
                    overlay_info["overlay_ratio"] = round((overlay_size / file_size) * 100, 2)
                    with open(self.malware_path, 'rb') as f:
                        f.seek(overlay_offset)
                        overlay_data = f.read(min(overlay_size, 1024 * 1024))
                    overlay_info["overlay_entropy"] = round(self.calculate_data_entropy(overlay_data), 4)
                    if len(overlay_data) >= 4:
                        magic = overlay_data[:4]
                        overlay_info["magic_bytes"] = magic.hex()
                        if magic == b'PK\x03\x04':
                            overlay_info["possible_content"] = "ZIP Archive"
                        elif magic == b'Rar!':
                            overlay_info["possible_content"] = "RAR Archive"
                        elif magic[:2] == b'MZ':
                            overlay_info["possible_content"] = "Embedded PE"
                        elif magic == b'\xca\xfe\xba\xbe':
                            overlay_info["possible_content"] = "Java Class/JAR"
                        elif magic == b'MSCF':
                            overlay_info["possible_content"] = "Microsoft CAB (Installer Payload)"
                            overlay_info["is_installer_payload"] = True
                        elif magic == b'\xef\xbe\xad\xde':
                            overlay_info["possible_content"] = "NSIS Installer Payload"
                            overlay_info["is_installer_payload"] = True
                        elif magic[:2] == b'7z':
                            overlay_info["possible_content"] = "7-Zip Archive"
                            overlay_info["is_installer_payload"] = True
                        elif overlay_info["overlay_entropy"] > 7.5:
                            overlay_info["possible_content"] = "Encrypted/Compressed Data"
                    is_installer_payload = overlay_info.get("is_installer_payload", False)
                    if not is_installer_payload:
                        if overlay_info["overlay_ratio"] > 50 or overlay_info["overlay_entropy"] > 7.0:
                            overlay_info["suspicious"] = True
            pe.close()
            self.results["overlay"] = overlay_info
            logger.info(f"Overlay analysis completed: {'Found' if overlay_info['has_overlay'] else 'Not found'}")
        except Exception as e:
            logger.error(f"Error analyzing overlay: {e}")
            self.results["overlay"] = {"error": str(e)}
    def analyze_version_info(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            version_info = {
                "has_version_info": False,
                "file_version": None,
                "product_version": None,
                "company_name": None,
                "product_name": None,
                "file_description": None,
                "original_filename": None,
                "internal_name": None,
                "legal_copyright": None,
                "filename_mismatch": False,
                "mismatch_type": None,
                "all_fields": {}
            }
            if hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    for info in file_info:
                        if hasattr(info, 'StringTable'):
                            for st in info.StringTable:
                                for entry in st.entries.items():
                                    key = entry[0].decode('utf-8', errors='ignore')
                                    value = entry[1].decode('utf-8', errors='ignore')
                                    version_info["all_fields"][key] = value
                                    field_map = {
                                        'CompanyName': 'company_name',
                                        'ProductName': 'product_name',
                                        'FileDescription': 'file_description',
                                        'OriginalFilename': 'original_filename',
                                        'InternalName': 'internal_name',
                                        'LegalCopyright': 'legal_copyright',
                                        'FileVersion': 'file_version',
                                        'ProductVersion': 'product_version'
                                    }
                                    if key in field_map:
                                        version_info[field_map[key]] = value
                                        version_info["has_version_info"] = True
            if version_info["original_filename"]:
                actual_name = self.malware_path.name.lower()
                original_name = version_info["original_filename"].lower()
                if original_name and original_name != actual_name:
                    version_info["filename_mismatch"] = True
                    actual_base = actual_name.rsplit('.', 1)[0].lower()
                    original_base = original_name.rsplit('.', 1)[0].lower()
                    shared_words = set(actual_base.split()) & set(original_base.split())
                    product_name = (version_info.get("product_name") or "").lower()
                    installer_words = ['setup', 'installer', 'install', 'update', 'updater']
                    both_installers = (any(w in actual_base for w in installer_words) and
                                      any(w in original_base for w in installer_words))
                    if shared_words or both_installers or product_name in actual_base:
                        version_info["mismatch_type"] = "benign_rename"
                    else:
                        version_info["mismatch_type"] = "suspicious_masquerade"
            pe.close()
            self.results["version_info"] = version_info
            logger.info(f"Version info analysis completed: {version_info.get('product_name', 'No product name')}")
        except Exception as e:
            logger.error(f"Error analyzing version info: {e}")
            self.results["version_info"] = {"error": str(e)}
    def map_capabilities(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            behavior_definitions = {
                "keylogging": {
                    "required_count": 2,
                    "primary_apis": ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
                                    "SetWindowsHookExA", "SetWindowsHookExW", "GetRawInputData",
                                    "RegisterRawInputDevices"],
                    "corroborating": ["WriteFile", "send", "InternetOpen"]
                },
                "screen_capture": {
                    "required_count": 3,
                    "primary_apis": ["BitBlt", "GetDC", "GetWindowDC", "CreateCompatibleDC",
                                    "CreateCompatibleBitmap", "GetDIBits", "PrintWindow",
                                    "StretchBlt", "GetDesktopWindow"],
                    "corroborating": ["WriteFile", "CreateFile", "InternetOpen", "send",
                                     "GdipSaveImageToFile", "SaveDC"]
                },
                "clipboard_access": {
                    "required_count": 2,
                    "primary_apis": ["OpenClipboard", "GetClipboardData", "SetClipboardData",
                                    "EmptyClipboard"],
                    "corroborating": []
                },
                "process_injection": {
                    "required_count": 2,
                    "primary_apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                                    "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
                                    "NtUnmapViewOfSection", "NtMapViewOfSection", "RtlCreateUserThread"],
                    "corroborating": ["OpenProcess"]
                },
                "persistence": {
                    "required_count": 1,
                    "primary_apis": ["CreateServiceA", "CreateServiceW"],
                    "corroborating": []
                },
                "registry_activity": {
                    "required_count": 1,
                    "primary_apis": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                                    "RegCreateKeyExW"],
                    "corroborating": [],
                    "note": "Normal for installers - not an indicator of malice"
                },
                "privilege_escalation": {
                    "required_count": 2,
                    "primary_apis": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
                                    "ImpersonateLoggedOnUser", "DuplicateToken", "SetTokenInformation"],
                    "corroborating": []
                },
                "credential_theft": {
                    "required_count": 1,
                    "primary_apis": ["CredEnumerate", "CredRead", "LsaRetrievePrivateData",
                                    "CryptUnprotectData", "SamConnect", "SamQueryInformationUser"],
                    "corroborating": []
                },
                "anti_debug": {
                    "required_count": 2,
                    "primary_apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                                    "NtQueryInformationProcess"],
                    "corroborating": [],
                    "note": "Common in Chromium-based apps - developer hygiene, not evasion"
                },
                "timing_evasion": {
                    "required_count": 2,
                    "primary_apis": ["GetTickCount", "QueryPerformanceCounter", "GetTickCount64",
                                    "timeGetTime"],
                    "corroborating": ["Sleep", "SleepEx"]
                },
                "network_communication": {
                    "required_count": 2,
                    "primary_apis": ["InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
                                    "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
                                    "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen",
                                    "socket", "connect", "send", "recv", "WSAStartup"],
                    "corroborating": []
                },
                "dll_loading": {
                    "required_count": 2,
                    "primary_apis": ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                                    "GetProcAddress", "LdrLoadDll"],
                    "corroborating": []
                },
                "ransomware_behavior": {
                    "required_count": 2,
                    "primary_apis": ["CryptEncrypt", "CryptDecrypt", "CryptGenKey",
                                    "CryptAcquireContextA", "CryptAcquireContextW",
                                    "CryptImportKey", "CryptExportKey", "CryptDestroyKey",
                                    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
                                    "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW"],
                    "corroborating": ["MoveFileA", "MoveFileW", "DeleteFileA", "DeleteFileW",
                                     "SetFileAttributesA", "SetFileAttributesW", "WriteFile"]
                },
                "file_enumeration": {
                    "required_count": 2,
                    "primary_apis": ["FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
                                    "GetLogicalDrives", "GetDriveTypeA", "GetDriveTypeW",
                                    "SHGetFolderPathA", "SHGetFolderPathW"],
                    "corroborating": []
                },
                "file_destruction": {
                    "required_count": 1,
                    "primary_apis": ["DeleteFileA", "DeleteFileW", "RemoveDirectoryA", "RemoveDirectoryW",
                                    "SHFileOperationA", "SHFileOperationW"],
                    "corroborating": ["FindFirstFileA", "FindFirstFileW"]
                },
                "process_termination": {
                    "required_count": 1,
                    "primary_apis": ["TerminateProcess", "NtTerminateProcess"],
                    "corroborating": ["OpenProcess", "CreateToolhelp32Snapshot", "Process32First"]
                }
            }
            capabilities = {
                "detected_behaviors": [],
                "behavior_details": {},
                "confidence_levels": {},
                "risk_indicators": [],
                "total_suspicious_apis": 0,
                "notes": []
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                all_imports = set()
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            all_imports.add(imp.name.decode('utf-8', errors='ignore'))
                for behavior, definition in behavior_definitions.items():
                    primary_matched = [api for api in definition["primary_apis"] if api in all_imports]
                    corroborating_matched = [api for api in definition.get("corroborating", []) if api in all_imports]
                    if len(primary_matched) >= definition["required_count"]:
                        if corroborating_matched:
                            confidence = "high"
                        elif len(primary_matched) >= definition["required_count"] + 2:
                            confidence = "high"
                        elif len(primary_matched) >= definition["required_count"]:
                            confidence = "medium"
                        else:
                            confidence = "low"
                        capabilities["detected_behaviors"].append(behavior)
                        capabilities["behavior_details"][behavior] = {
                            "apis": primary_matched,
                            "corroborating": corroborating_matched
                        }
                        capabilities["confidence_levels"][behavior] = confidence
                        capabilities["total_suspicious_apis"] += len(primary_matched)
                    elif len(primary_matched) > 0 and behavior in ["screen_capture"]:
                        capabilities["notes"].append(
                            f"Found {len(primary_matched)} {behavior} API(s) but below threshold - "
                            f"likely normal GUI operations: {primary_matched}"
                        )
                high_risk_behaviors = ["process_injection", "credential_theft", "privilege_escalation",
                                      "ransomware_behavior", "file_destruction", "process_termination"]
                for behavior in capabilities["detected_behaviors"]:
                    if behavior in high_risk_behaviors:
                        conf = capabilities["confidence_levels"].get(behavior, "low")
                        if conf in ["high", "medium"]:
                            capabilities["risk_indicators"].append(
                                f"High-risk behavior: {behavior} (confidence: {conf})"
                            )
                        elif conf == "low" and behavior in ["ransomware_behavior", "process_termination"]:
                            capabilities["risk_indicators"].append(
                                f"Potential {behavior} detected (confidence: {conf})"
                            )
                    elif behavior == "keylogging":
                        conf = capabilities["confidence_levels"].get(behavior, "low")
                        capabilities["risk_indicators"].append(
                            f"Keylogging capability detected (confidence: {conf})"
                        )
            pe.close()
            self.results["capability_mapping"] = capabilities
            logger.info(f"Capability mapping completed: {len(capabilities['detected_behaviors'])} behaviors detected")
        except Exception as e:
            logger.error(f"Error mapping capabilities: {e}")
            self.results["capability_mapping"] = {"error": str(e)}
    def scan_yara_rules(self, rules_path: str = None):
        try:
            yara_results = {
                "matches": [],
                "malware_families": [],
                "tags": [],
                "rule_sources": []
            }
            rules_paths = [
                '/opt/yara-rules/rules/malware',
                '/opt/yara-rules/signature-base/yara',
                '/usr/share/yara-rules',
                rules_path
            ] if rules_path else [
                '/opt/yara-rules/rules/malware',
                '/opt/yara-rules/signature-base/yara'
            ]
            compiled_rules = []
            builtin_rules = """
            rule Suspicious_Strings {
                meta:
                    description = "Detects suspicious string patterns"
                strings:
                    $s1 = "cmd.exe" nocase
                    $s2 = "powershell" nocase
                    $s3 = "mimikatz" nocase
                    $s4 = "password" nocase
                    $s5 = "keylog" nocase
                condition:
                    2 of them
            }
            rule Possible_Ransomware {
                meta:
                    description = "Detects possible ransomware indicators"
                strings:
                    $r1 = "encrypt" nocase
                    $r2 = "bitcoin" nocase
                    $r3 = "ransom" nocase
                    $r4 = "decrypt" nocase
                    $r5 = ".onion" nocase
                condition:
                    2 of them
            }
            rule Possible_RAT {
                meta:
                    description = "Detects possible RAT indicators"
                strings:
                    $rat1 = "backdoor" nocase
                    $rat2 = "reverse" nocase
                    $rat3 = "shell" nocase
                    $rat4 = "webcam" nocase
                    $rat5 = "keylogger" nocase
                condition:
                    2 of them
            }
            """
            try:
                builtin = yara.compile(source=builtin_rules)
                compiled_rules.append(('builtin', builtin))
            except:
                pass
            for rule_path in rules_paths:
                if rule_path and os.path.exists(rule_path):
                    try:
                        if os.path.isdir(rule_path):
                            for root, dirs, files in os.walk(rule_path):
                                for file in files[:10]:
                                    if file.endswith('.yar') or file.endswith('.yara'):
                                        try:
                                            rule = yara.compile(os.path.join(root, file))
                                            compiled_rules.append((file, rule))
                                            yara_results["rule_sources"].append(os.path.join(root, file))
                                        except:
                                            pass
                        else:
                            rule = yara.compile(rule_path)
                            compiled_rules.append((os.path.basename(rule_path), rule))
                            yara_results["rule_sources"].append(rule_path)
                    except:
                        pass
            for source, rules in compiled_rules:
                try:
                    matches = rules.match(str(self.malware_path))
                    for match in matches:
                        match_info = {
                            "rule": match.rule,
                            "source": source,
                            "tags": list(match.tags) if match.tags else [],
                            "meta": dict(match.meta) if match.meta else {},
                            "strings_matched": len(match.strings)
                        }
                        yara_results["matches"].append(match_info)
                        yara_results["tags"].extend(match_info["tags"])
                        if 'family' in match.meta:
                            yara_results["malware_families"].append(match.meta['family'])
                        elif any(x in match.rule.lower() for x in ['ransomware', 'rat', 'trojan', 'worm', 'virus']):
                            yara_results["malware_families"].append(match.rule)
                except:
                    pass
            yara_results["tags"] = list(set(yara_results["tags"]))
            yara_results["malware_families"] = list(set(yara_results["malware_families"]))
            self.results["yara_matches"] = yara_results
            logger.info(f"YARA scanning completed: {len(yara_results['matches'])} matches")
        except Exception as e:
            logger.error(f"Error scanning with YARA rules: {e}")
            self.results["yara_matches"] = {"error": str(e)}
    def analyze_authenticode(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            authenticode = {
                "is_signed": False,
                "signature_valid": None,
                "signer": None,
                "issuer": None,
                "timestamp": None,
                "certificate_chain": [],
                "verification_status": "Not Signed"
            }
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                authenticode["is_signed"] = True
                authenticode["verification_status"] = "Signed (verification requires external tools)"
                with open(self.malware_path, 'rb') as f:
                    f.seek(security_dir.VirtualAddress)
                    sig_data = f.read(security_dir.Size)
                try:
                    result = subprocess.run(
                        ['osslsigncode', 'verify', str(self.malware_path)],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if 'Subject:' in result.stdout:
                        for line in result.stdout.split('\n'):
                            if 'Subject:' in line:
                                authenticode["signer"] = line.split('Subject:')[1].strip()
                            if 'Issuer:' in line:
                                authenticode["issuer"] = line.split('Issuer:')[1].strip()
                    authenticode["signature_valid"] = result.returncode == 0
                except FileNotFoundError:
                    try:
                        result = subprocess.run(
                            ['sigcheck', '-nobanner', str(self.malware_path)],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        authenticode["raw_output"] = result.stdout
                    except:
                        authenticode["note"] = "Install osslsigncode for full signature analysis"
                except:
                    pass
            pe.close()
            self.results["authenticode"] = authenticode
            logger.info(f"Authenticode analysis completed: {'Signed' if authenticode['is_signed'] else 'Not signed'}")
        except Exception as e:
            logger.error(f"Error analyzing Authenticode: {e}")
            self.results["authenticode"] = {"error": str(e)}
    def categorize_imports_by_behavior(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            categories = {
                "persistence": {
                    "apis": ["RegSetValue", "RegCreateKey", "CreateService", "WritePrivateProfileString",
                            "SHSetValue", "SetFileAttributes", "CopyFile", "MoveFile"],
                    "found": []
                },
                "input_capture": {
                    "apis": ["GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "SetWindowsHookEx",
                            "GetRawInputData", "RegisterRawInputDevices", "GetClipboardData"],
                    "found": []
                },
                "injection": {
                    "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
                            "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "RtlCreateUserThread"],
                    "found": []
                },
                "evasion": {
                    "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                            "GetTickCount", "QueryPerformanceCounter", "Sleep", "VirtualProtect"],
                    "found": []
                },
                "privilege": {
                    "apis": ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
                            "ImpersonateLoggedOnUser", "DuplicateToken", "SetTokenInformation", "EnablePrivilege"],
                    "found": []
                },
                "network": {
                    "apis": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
                            "URLDownloadToFile", "WinHttpOpen", "socket", "connect", "WSASend",
                            "sendto", "recv", "WSARecv", "WSAConnect"],
                    "found": []
                },
                "crypto": {
                    "apis": ["CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
                            "CryptImportKey", "CryptExportKey", "BCryptEncrypt", "BCryptDecrypt"],
                    "found": []
                },
                "destruction": {
                    "apis": ["DeleteFile", "RemoveDirectory", "SHFileOperation", "MoveFileEx",
                            "FormatMessage", "ExitWindowsEx", "InitiateSystemShutdown"],
                    "found": []
                }
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            for category, data in categories.items():
                                for api in data["apis"]:
                                    if api.lower() in func_name.lower():
                                        if func_name not in data["found"]:
                                            data["found"].append(func_name)
            import_summary = {
                "categories": {k: {"count": len(v["found"]), "imports": v["found"]}
                              for k, v in categories.items()},
                "high_risk_categories": [k for k, v in categories.items()
                                        if len(v["found"]) > 0 and k in ["injection", "privilege", "input_capture"]],
                "total_categorized": sum(len(v["found"]) for v in categories.values())
            }
            pe.close()
            self.results["import_categories"] = import_summary
            logger.info(f"Import categorization completed: {import_summary['total_categorized']} APIs categorized")
        except Exception as e:
            logger.error(f"Error categorizing imports: {e}")
            self.results["import_categories"] = {"error": str(e)}
    def analyze_entry_point(self):
        try:
            pe = pefile.PE(str(self.malware_path))
            ep_analysis = {
                "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "entry_point_section": None,
                "first_bytes": None,
                "suspicious_patterns": [],
                "heuristics": []
            }
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if section.VirtualAddress <= ep_rva < section.VirtualAddress + section.Misc_VirtualSize:
                    ep_analysis["entry_point_section"] = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    break
            try:
                ep_offset = pe.get_offset_from_rva(ep_rva)
                with open(self.malware_path, 'rb') as f:
                    f.seek(ep_offset)
                    first_bytes = f.read(32)
                    ep_analysis["first_bytes"] = first_bytes.hex()
                    if first_bytes[0] == 0x60:
                        ep_analysis["suspicious_patterns"].append("PUSHAD at entry (common in packers)")
                    if first_bytes[0] == 0xE9:
                        ep_analysis["suspicious_patterns"].append("JMP instruction at entry point")
                    if first_bytes[:4] == b'\x90\x90\x90\x90':
                        ep_analysis["suspicious_patterns"].append("NOP sled at entry")
                    if 0xCC in first_bytes[:16]:
                        ep_analysis["suspicious_patterns"].append("INT3 (breakpoint) in entry code")
                    if b'\x0F\x31' in first_bytes:
                        ep_analysis["suspicious_patterns"].append("RDTSC instruction (timing check)")
                    if b'\xFF\x15' in first_bytes:
                        ep_analysis["heuristics"].append("Indirect call near entry point")
            except:
                pass
            if ep_analysis["entry_point_section"] and ep_analysis["entry_point_section"] not in ['.text', '.code', 'CODE']:
                ep_analysis["suspicious_patterns"].append(f"Entry point in unusual section: {ep_analysis['entry_point_section']}")
            pe.close()
            self.results["entry_point_analysis"] = ep_analysis
            logger.info(f"Entry point analysis completed: {len(ep_analysis['suspicious_patterns'])} suspicious patterns")
        except Exception as e:
            logger.error(f"Error analyzing entry point: {e}")
            self.results["entry_point_analysis"] = {"error": str(e)}
    def detect_config_blobs(self):
        try:
            with open(self.malware_path, 'rb') as f:
                data = f.read()
            is_container = not self.is_pe_file()
            is_installer = self.results.get("installer_info", {}).get("is_installer", False)
            config_detection = {
                "potential_configs": [],
                "xor_patterns": [],
                "base64_blobs": [],
                "high_entropy_regions": [],
                "confidence": "high" if not is_container else "low",
                "note": ""
            }
            if is_container or is_installer:
                config_detection["note"] = (
                    "Low confidence: Patterns found in compressed container may be "
                    "CAB compression artifacts, not malware configurations"
                )
            for xor_key in range(1, 256):
                xored_http = bytes([b ^ xor_key for b in b'http'])
                if xored_http in data:
                    pos = data.find(xored_http)
                    sample = data[pos:pos+20]
                    decoded = bytes([b ^ xor_key for b in sample])
                    if b'http' in decoded and all(32 <= b < 127 for b in decoded if b != 0):
                        config_detection["xor_patterns"].append({
                            "key": hex(xor_key),
                            "offset": pos,
                            "decoded_sample": decoded.decode('utf-8', errors='ignore'),
                            "confidence": "low" if is_container else "medium"
                        })
                        break
            if not is_container:
                b64_pattern = re.compile(b'[A-Za-z0-9+/]{40,}={0,2}')
                b64_matches = b64_pattern.findall(data)
                for match in b64_matches[:5]:
                    try:
                        import base64
                        decoded = base64.b64decode(match)
                        if len(decoded) > 10:
                            config_detection["base64_blobs"].append({
                                "length": len(match),
                                "decoded_preview": decoded[:50].hex()
                            })
                    except:
                        pass
            if not is_container:
                chunk_size = 256
                for i in range(0, len(data) - chunk_size, chunk_size):
                    chunk = data[i:i+chunk_size]
                    entropy = self.calculate_data_entropy(chunk)
                    if entropy > 7.5:
                        config_detection["high_entropy_regions"].append({
                            "offset": hex(i),
                            "size": chunk_size,
                            "entropy": round(entropy, 4)
                        })
                        if len(config_detection["high_entropy_regions"]) >= 10:
                            break
            self.results["config_detection"] = config_detection
            logger.info(f"Config blob detection completed: {len(config_detection['xor_patterns'])} XOR patterns, {len(config_detection['base64_blobs'])} Base64 blobs")
        except Exception as e:
            logger.error(f"Error detecting config blobs: {e}")
            self.results["config_detection"] = {"error": str(e)}
    def detect_instruction_anti_debug(self):
        try:
            if not self.is_pe_file():
                self.results["instruction_anti_debug"] = {
                    "skipped": True,
                    "reason": "Not a PE file - instruction analysis not applicable",
                    "techniques_found": [],
                    "note": "Container files (MSI/CAB/ZIP) contain compressed data that matches opcode patterns by coincidence"
                }
                logger.info("Instruction anti-debug skipped: not a PE file")
                return
            with open(self.malware_path, 'rb') as f:
                data = f.read()
            anti_debug = {
                "techniques_found": [],
                "skipped": False,
                "rdtsc_count": 0,
                "cpuid_count": 0,
                "int3_count": 0,
                "int2d_count": 0,
                "seh_manipulation": False
            }
            rdtsc_pattern = b'\x0F\x31'
            anti_debug["rdtsc_count"] = data.count(rdtsc_pattern)
            if anti_debug["rdtsc_count"] > 2:
                anti_debug["techniques_found"].append("RDTSC timing checks")
            cpuid_pattern = b'\x0F\xA2'
            anti_debug["cpuid_count"] = data.count(cpuid_pattern)
            if anti_debug["cpuid_count"] > 0:
                anti_debug["techniques_found"].append("CPUID instruction (VM detection)")
            int3_count = data.count(b'\xCC')
            anti_debug["int3_count"] = min(int3_count, 100)
            if int3_count > 10 and int3_count < 1000:
                anti_debug["techniques_found"].append("INT3 anti-debug traps")
            int2d_pattern = b'\xCD\x2D'
            anti_debug["int2d_count"] = data.count(int2d_pattern)
            if anti_debug["int2d_count"] > 0:
                anti_debug["techniques_found"].append("INT 2D kernel debugger check")
            seh_patterns = [
                b'\x64\xA1\x00\x00\x00\x00',
                b'\x64\x89\x25\x00\x00\x00\x00',
            ]
            for pattern in seh_patterns:
                if pattern in data:
                    anti_debug["seh_manipulation"] = True
                    anti_debug["techniques_found"].append("SEH-based anti-debug")
                    break
            if b'IsDebuggerPresent' in data:
                anti_debug["techniques_found"].append("IsDebuggerPresent API call")
            if b'NtQueryInformationProcess' in data:
                anti_debug["techniques_found"].append("NtQueryInformationProcess (ProcessDebugPort)")
            self.results["instruction_anti_debug"] = anti_debug
            logger.info(f"Instruction anti-debug detection completed: {len(anti_debug['techniques_found'])} techniques")
        except Exception as e:
            logger.error(f"Error detecting instruction anti-debug: {e}")
            self.results["instruction_anti_debug"] = {"error": str(e)}
    def correlate_threat_intel(self):
        try:
            sha256 = self.results.get("hashes", {}).get("sha256")
            md5 = self.results.get("hashes", {}).get("md5")
            threat_intel = {
                "hash_lookup": {
                    "md5": md5,
                    "sha256": sha256,
                    "lookup_status": "pending"
                },
                "virustotal": {
                    "detected": False,
                    "positives": 0,
                    "total": 0,
                    "malware_names": [],
                    "scan_date": None,
                    "permalink": None,
                    "status": "not_queried"
                },
                "imphash_clustering": {
                    "imphash": self.results.get("pe_analysis", {}).get("imphash"),
                    "similar_samples": [],
                    "note": "Imphash can be used to find related samples"
                },
                "ssdeep_similarity": {
                    "ssdeep": self.results.get("hashes", {}).get("ssdeep"),
                    "similar_samples": [],
                    "note": "SSDeep fuzzy hash for similarity matching"
                },
                "known_iocs": [],
                "api_endpoints": {
                    "virustotal": "https://www.virustotal.com/api/v3/",
                }
            }
            vt_api_key = os.environ.get("VT_API_KEY", "")
            if not vt_api_key:
                vt_api_key = self.config.get("tools", {}).get("virustotal_api_key", "") if self.config else ""
            if vt_api_key and sha256:
                try:
                    import requests
                    headers = {"x-apikey": vt_api_key}
                    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                    logger.info(f"Querying VirusTotal for hash: {sha256[:16]}...")
                    response = requests.get(url, headers=headers, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                        total = sum(stats.values())
                        malware_names = []
                        results = attrs.get("last_analysis_results", {})
                        for engine, result in results.items():
                            if result.get("category") == "malicious" and result.get("result"):
                                name = result.get("result")
                                if name and name not in malware_names:
                                    malware_names.append(name)
                        threat_intel["virustotal"] = {
                            "detected": positives > 0,
                            "positives": positives,
                            "total": total,
                            "malware_names": malware_names[:10],
                            "scan_date": attrs.get("last_analysis_date"),
                            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                            "status": "found",
                            "reputation": attrs.get("reputation", 0),
                            "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
                        }
                        threat_intel["hash_lookup"]["lookup_status"] = "completed"
                        logger.info(f"VirusTotal: {positives}/{total} detections")
                    elif response.status_code == 404:
                        threat_intel["virustotal"]["status"] = "not_found"
                        threat_intel["hash_lookup"]["lookup_status"] = "hash_unknown"
                        logger.info("VirusTotal: Hash not found in database")
                    elif response.status_code == 401:
                        threat_intel["virustotal"]["status"] = "auth_error"
                        threat_intel["hash_lookup"]["lookup_status"] = "invalid_api_key"
                        logger.warning("VirusTotal: Invalid API key")
                    elif response.status_code == 429:
                        threat_intel["virustotal"]["status"] = "rate_limited"
                        threat_intel["hash_lookup"]["lookup_status"] = "rate_limited"
                        logger.warning("VirusTotal: Rate limit exceeded")
                    else:
                        threat_intel["virustotal"]["status"] = f"error_{response.status_code}"
                        logger.warning(f"VirusTotal: HTTP {response.status_code}")
                except ImportError:
                    threat_intel["virustotal"]["status"] = "requests_not_installed"
                    logger.warning("VirusTotal: 'requests' library not installed")
                except requests.exceptions.Timeout:
                    threat_intel["virustotal"]["status"] = "timeout"
                    logger.warning("VirusTotal: Request timed out")
                except Exception as e:
                    threat_intel["virustotal"]["status"] = f"error: {str(e)}"
                    logger.warning(f"VirusTotal lookup failed: {e}")
            else:
                if not vt_api_key:
                    threat_intel["virustotal"]["status"] = "no_api_key"
                    threat_intel["hash_lookup"]["lookup_status"] = "no_api_key_configured"
            ioc_patterns = {
                "c2_urls": self.results.get("strings", {}).get("urls", []),
                "suspicious_ips": self.results.get("strings", {}).get("ips", []),
                "bitcoin_addresses": []
            }
            btc_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
            all_strings = str(self.results.get("strings", {}))
            btc_matches = btc_pattern.findall(all_strings)
            ioc_patterns["bitcoin_addresses"] = btc_matches[:5]
            threat_intel["known_iocs"] = ioc_patterns
            self.results["threat_intel"] = threat_intel
            logger.info("Threat intelligence correlation completed")
        except Exception as e:
            logger.error(f"Error correlating threat intel: {e}")
            self.results["threat_intel"] = {"error": str(e)}
    def detect_installer_framework(self):
        try:
            installer_info = {
                "is_installer": False,
                "framework": None,
                "confidence": 0.0,
                "evidence": []
            }
            with open(self.malware_path, 'rb') as f:
                file_data = f.read()
                file_start = file_data[:4096]
            all_strings = str(self.results.get("strings", {}))
            version_info = self.results.get("version_info", {})
            overlay = self.results.get("overlay", {})
            nsis_indicators = 0
            if b'\xef\xbe\xad\xde' in file_data:
                nsis_indicators += 3
                installer_info["evidence"].append("NSIS magic bytes found")
            if 'nullsoft' in all_strings.lower() or 'nsis' in all_strings.lower():
                nsis_indicators += 2
                installer_info["evidence"].append("NSIS/Nullsoft strings found")
            if 'nsis.sf.net' in all_strings.lower():
                nsis_indicators += 2
                installer_info["evidence"].append("NSIS support URL found")
            if nsis_indicators >= 3:
                installer_info["is_installer"] = True
                installer_info["framework"] = "NSIS"
                installer_info["confidence"] = min(1.0, nsis_indicators / 5)
            if not installer_info["is_installer"]:
                inno_indicators = 0
                if 'inno setup' in all_strings.lower():
                    inno_indicators += 3
                    installer_info["evidence"].append("Inno Setup string found")
                if b'Inno Setup Setup Data' in file_data:
                    inno_indicators += 3
                    installer_info["evidence"].append("Inno Setup header found")
                if inno_indicators >= 3:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "InnoSetup"
                    installer_info["confidence"] = min(1.0, inno_indicators / 4)
            if not installer_info["is_installer"]:
                if file_start[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                    mime = self.results.get("metadata", {}).get("mime_type", "")
                    if 'ms-installer' in mime or 'msi' in mime.lower():
                        installer_info["is_installer"] = True
                        installer_info["framework"] = "MSI"
                        installer_info["confidence"] = 0.95
                        installer_info["evidence"].append("MSI OLE compound file structure")
            if not installer_info["is_installer"]:
                if 'wix' in all_strings.lower() or 'windows installer xml' in all_strings.lower():
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "WiX"
                    installer_info["confidence"] = 0.7
                    installer_info["evidence"].append("WiX Toolset markers found")
            if not installer_info["is_installer"]:
                if 'installshield' in all_strings.lower():
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "InstallShield"
                    installer_info["confidence"] = 0.8
                    installer_info["evidence"].append("InstallShield strings found")
            if not installer_info["is_installer"]:
                electron_indicators = 0
                if 'electron' in all_strings.lower():
                    electron_indicators += 2
                if 'node.dll' in all_strings.lower() or 'libnode' in all_strings.lower():
                    electron_indicators += 2
                if 'chromium' in all_strings.lower():
                    electron_indicators += 1
                if electron_indicators >= 3:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "Electron"
                    installer_info["confidence"] = min(1.0, electron_indicators / 4)
                    installer_info["evidence"].append("Electron/Node.js application detected")
            if not installer_info["is_installer"]:
                sfx7z_indicators = 0
                if b'7z\xbc\xaf\x27\x1c' in file_data:
                    sfx7z_indicators += 3
                    installer_info["evidence"].append("7-Zip archive magic bytes found")
                if b'7-Zip' in file_data or b'7z.sfx' in file_data.lower():
                    sfx7z_indicators += 2
                    installer_info["evidence"].append("7-Zip SFX strings found")
                if b'7-Zip: Internal Error' in file_data or b'7-Zip Errors' in file_data:
                    sfx7z_indicators += 2
                    installer_info["evidence"].append("7-Zip error strings found")
                if overlay.get("has_overlay") and overlay.get("overlay_ratio", 0) > 40:
                    sfx7z_indicators += 1
                if sfx7z_indicators >= 3:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "7-Zip SFX"
                    installer_info["confidence"] = min(1.0, sfx7z_indicators / 5)
            if not installer_info["is_installer"]:
                packer_info = self.results.get("packer_detection", {})
                detected_packers = packer_info.get("packers_detected", [])
                is_upx = any('upx' in p.lower() for p in detected_packers) or packer_info.get("likely_packed", False)
                pe_sections = self.results.get("pe_analysis", {}).get("sections", [])
                has_upx_section = any('upx' in s.get("name", "").lower() for s in pe_sections)
                overlay_ratio = overlay.get("overlay_ratio", 0)
                if (is_upx or has_upx_section) and overlay_ratio > 30:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "UPX SFX Archive"
                    installer_info["confidence"] = 0.85 if overlay_ratio > 50 else 0.7
                    installer_info["evidence"].append(f"UPX packed + {overlay_ratio:.0f}% overlay → SFX pattern")
                    installer_info["evidence"].append("Common for Firefox, Brave, other browser installers")
            if not installer_info["is_installer"]:
                if b'Rar!\x1a\x07' in file_data:
                    if overlay.get("has_overlay") and overlay.get("overlay_ratio", 0) > 30:
                        installer_info["is_installer"] = True
                        installer_info["framework"] = "RAR SFX"
                        installer_info["confidence"] = 0.85
                        installer_info["evidence"].append("RAR archive in overlay → SFX installer")
            if not installer_info["is_installer"]:
                if b'WinRAR SFX' in file_data or b'SFX module' in file_data:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "WinRAR SFX"
                    installer_info["confidence"] = 0.9
                    installer_info["evidence"].append("WinRAR SFX module strings found")
            if not installer_info["is_installer"]:
                generic_indicators = 0
                if overlay.get("is_installer_payload"):
                    generic_indicators += 3
                    installer_info["evidence"].append(f"Installer payload detected: {overlay.get('possible_content', 'Unknown')}")
                product_name = str(version_info.get("product_name", "")).lower()
                file_desc = str(version_info.get("file_description", "")).lower()
                installer_keywords = ['setup', 'installer', 'install', 'update', 'updater', 'uninstall']
                for kw in installer_keywords:
                    if kw in product_name or kw in file_desc:
                        generic_indicators += 1
                        installer_info["evidence"].append(f"Installer keyword in metadata: {kw}")
                if overlay.get("has_overlay") and overlay.get("overlay_ratio", 0) > 30:
                    generic_indicators += 1
                    installer_info["evidence"].append("Large overlay (common in installers)")
                if generic_indicators >= 2:
                    installer_info["is_installer"] = True
                    installer_info["framework"] = "Generic Installer"
                    installer_info["confidence"] = min(0.9, generic_indicators / 4)
            self.results["installer_info"] = installer_info
            if installer_info["is_installer"]:
                logger.info(f"Installer detected: {installer_info['framework']} (confidence: {installer_info['confidence']:.0%})")
            else:
                logger.info("No installer framework detected")
        except Exception as e:
            logger.error(f"Error detecting installer framework: {e}")
            self.results["installer_info"] = {"is_installer": False, "error": str(e)}
    def classify_file_role(self):
        try:
            role_info = {
                "role": "unknown",
                "confidence": "low",
                "signals": [],
                "note": ""
            }
            installer = self.results.get("installer_info", {})
            if installer.get("is_installer"):
                role_info["role"] = "installer"
                role_info["confidence"] = "high" if installer.get("confidence", 0) > 0.7 else "medium"
                role_info["signals"].append(f"Installer framework: {installer.get('framework')}")
                self.results["file_role"] = role_info
                logger.info(f"File role classified: {role_info['role']} ({role_info['confidence']})")
                return
            pe_header = self.results.get("pe_analysis", {}).get("header", {})
            if pe_header:
                chars = pe_header.get("characteristics", "0x0")
                try:
                    chars_int = int(chars, 16) if isinstance(chars, str) else chars
                    if chars_int & 0x2000:
                        role_info["role"] = "library"
                        role_info["confidence"] = "high"
                        role_info["signals"].append("PE DLL characteristic flag set")
                        self.results["file_role"] = role_info
                        logger.info(f"File role classified: {role_info['role']}")
                        return
                except:
                    pass
            packer = self.results.get("packer_detection", {})
            overlay = self.results.get("overlay", {})
            overlay_ratio = overlay.get("overlay_ratio", 0)
            if packer.get("likely_packed") and overlay_ratio > 30:
                role_info["role"] = "installer"
                role_info["confidence"] = "medium"
                role_info["signals"].append(f"Packer + {overlay_ratio:.0f}% overlay → likely SFX")
                self.results["file_role"] = role_info
                logger.info(f"File role classified: {role_info['role']} (SFX pattern)")
                return
            file_size = self.results.get("metadata", {}).get("file_size", 0)
            has_network = "network_communication" in self.results.get("capability_mapping", {}).get("detected_behaviors", [])
            has_file_writes = "CreateFile" in str(self.results.get("imports_exports", {}))
            if file_size < 100000 and has_network and overlay_ratio < 10:
                role_info["role"] = "loader_dropper"
                role_info["confidence"] = "low"
                role_info["signals"].append("Small size + network capability")
                role_info["note"] = "Potential loader/dropper pattern - needs further analysis"
            else:
                version_info = self.results.get("version_info", {})
                if version_info.get("has_version_info"):
                    role_info["role"] = "application"
                    role_info["confidence"] = "medium"
                    role_info["signals"].append("Has version info")
                else:
                    role_info["role"] = "unknown"
                    role_info["confidence"] = "low"
                    role_info["note"] = "Cannot determine file role - scoring will be conservative"
            self.results["file_role"] = role_info
            logger.info(f"File role classified: {role_info['role']} ({role_info['confidence']})")
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error classifying file role: {e}")
            self.results["file_role"] = {"role": "unknown", "error": str(e)}
    def is_windows_system_tool(self) -> bool:
        WINDOWS_SYSTEM_TOOLS = {
            'ipconfig.exe', 'nslookup.exe', 'netstat.exe', 'ping.exe', 'tracert.exe',
            'netsh.exe', 'route.exe', 'arp.exe', 'nbtstat.exe', 'hostname.exe',
            'nfsadmin.exe', 'rpcinfo.exe', 'ftp.exe',
            'rundll32.exe', 'regsvr32.exe', 'sfc.exe', 'cipher.exe', 'takeown.exe',
            'icacls.exe', 'shutdown.exe', 'tasklist.exe', 'taskkill.exe', 'lodctr.exe',
            'unlodctr.exe', 'findstr.exe', 'forfiles.exe', 'where.exe', 'waitfor.exe',
            'compact.exe', 'expand.exe', 'bootcfg.exe', 'driverquery.exe',
            'eventcreate.exe', 'eventvwr.exe', 'relog.exe', 'tzutil.exe',
            'sxstrace.exe', 'winver.exe', 'setx.exe', 'regini.exe',
            'wmic.exe', 'winrm.exe', 'winrs.exe', 'cscript.exe', 'wscript.exe',
            'wmplayer.exe', 'wmpnscfg.exe', 'wmpnetwk.exe', 'wmpshare.exe', 'wmpconfig.exe',
            'runonce.exe', 'grpconv.exe', 'cmd.exe', 'powershell.exe',
            'msiexec.exe', 'cmstp.exe', 'certutil.exe',
        }
        filename = self.malware_path.name.lower()
        if filename in WINDOWS_SYSTEM_TOOLS:
            return True
        version = self.results.get("version_info", {})
        original_filename = str(version.get("original_filename", "")).lower()
        if original_filename in WINDOWS_SYSTEM_TOOLS:
            return True
        auth = self.results.get("authenticode", {})
        if auth.get("is_signed"):
            signer = str(auth.get("signer", "")).lower()
            if "microsoft" in signer:
                return True
        return False
    def is_known_admin_tool(self) -> bool:
        signals = []
        pdb_info = self.results.get("pdb_info", {})
        pdb_path = (pdb_info.get("pdb_path") or "").lower()
        sysinternals_patterns = ["sysinternals", "procmon", "procexp", "autoruns", "psexec", "handle"]
        if any(p in pdb_path for p in sysinternals_patterns):
            signals.append("sysinternals_pdb")
        version_info = self.results.get("version_info", {})
        company = str(version_info.get("company_name", "")).lower()
        product = str(version_info.get("product_name", "")).lower()
        admin_tool_vendors = ["sysinternals", "microsoft", "nirsoft", "x64dbg", "ollydbg"]
        admin_tool_products = ["process explorer", "process monitor", "autoruns", "regmon", "filemon",
                              "debugger", "disassembler", "resource hacker", "dependency walker"]
        if any(v in company for v in admin_tool_vendors):
            signals.append("admin_vendor")
        if any(p in product for p in admin_tool_products):
            signals.append("admin_product")
        import_cats = self.results.get("import_categories", {}).get("categories", {})
        imports = self.results.get("imports_exports", {}).get("imports", {})
        gui_dlls = ["user32.dll", "gdi32.dll", "comctl32.dll", "comdlg32.dll", "shell32.dll"]
        gui_import_count = sum(1 for dll in imports.keys() if dll.lower() in gui_dlls)
        if gui_import_count >= 4:
            signals.append("heavy_gui")
        auth = self.results.get("authenticode", {})
        if auth.get("is_signed"):
            signals.append("signed")
        is_admin_tool = len(signals) >= 2
        self.results["admin_tool_detection"] = {
            "is_admin_tool": is_admin_tool,
            "signals": signals,
            "note": "Sensitive API usage suppressed for admin tools" if is_admin_tool else ""
        }
        return is_admin_tool
    def analyze_api_clusters(self):
        try:
            CLUSTERS = {
                "injection": {
                    "required": {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory"},
                    "complete_with": {"CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"},
                    "intent": "Process injection - writing and executing code in another process",
                    "weight": 35
                },
                "debugger": {
                    "required": {"OpenProcess", "ReadProcessMemory"},
                    "complete_with": {"GetThreadContext", "SetThreadContext", "DebugActiveProcess"},
                    "negative": {"WriteProcessMemory", "CreateRemoteThread"},
                    "intent": "Debugging/inspection - reading process memory without modification",
                    "weight": 0
                },
                "hollow_process": {
                    "required": {"CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory"},
                    "complete_with": {"SetThreadContext", "ResumeThread"},
                    "intent": "Process hollowing - replacing legitimate process with malicious code",
                    "weight": 45
                },
                "credential_dump": {
                    "required": {"LsaRetrievePrivateData"},
                    "complete_with": {"SamConnect", "SamQueryInformationUser", "CryptUnprotectData"},
                    "intent": "Credential extraction from Windows security databases",
                    "weight": 40
                },
                "admin_tool_cred_display": {
                    "required": {"CredEnumerate", "CredRead"},
                    "context": "admin_tool",
                    "intent": "Credential enumeration for display (admin tool behavior)",
                    "weight": 0
                }
            }
            imports = self.results.get("imports_exports", {}).get("imports", {})
            all_apis = set()
            for dll, funcs in imports.items():
                for func in funcs:
                    if isinstance(func, dict):
                        all_apis.add(func.get("name", ""))
                    else:
                        all_apis.add(str(func))
            is_admin = self.is_known_admin_tool()
            matched_clusters = []
            for cluster_name, cluster_def in CLUSTERS.items():
                required = cluster_def.get("required", set())
                complete_with = cluster_def.get("complete_with", set())
                negative = cluster_def.get("negative", set())
                context = cluster_def.get("context")
                if context == "admin_tool" and not is_admin:
                    continue
                required_matches = required & all_apis
                if len(required_matches) >= len(required) * 0.8:
                    if negative and (negative & all_apis):
                        continue
                    complete_matches = complete_with & all_apis
                    confidence = "high" if complete_matches else "medium"
                    matched_clusters.append({
                        "cluster": cluster_name,
                        "intent": cluster_def["intent"],
                        "weight": cluster_def["weight"],
                        "confidence": confidence,
                        "matched_apis": list(required_matches | complete_matches)
                    })
            self.results["api_clusters"] = {
                "clusters_detected": matched_clusters,
                "is_admin_tool": is_admin,
                "total_malicious_weight": sum(c["weight"] for c in matched_clusters if c["weight"] > 0)
            }
            logger.info(f"API cluster analysis: {len(matched_clusters)} clusters detected")
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error analyzing API clusters: {e}")
            self.results["api_clusters"] = {"error": str(e)}
    def calculate_benign_indicators(self):
        try:
            benign_info = {
                "benign_score": 0,
                "evidence": [],
                "context_notes": []
            }
            score = 0
            auth = self.results.get("authenticode", {})
            if auth.get("is_signed"):
                if auth.get("signature_valid", False):
                    score += 30
                    benign_info["evidence"].append("Valid code signature from trusted publisher")
                else:
                    score += 10
                    benign_info["evidence"].append("Code signature present (validity unclear)")
            installer = self.results.get("installer_info", {})
            if installer.get("is_installer"):
                confidence = installer.get("confidence", 0.5)
                points = int(25 * confidence)
                score += points
                benign_info["evidence"].append(f"Recognized installer: {installer.get('framework')}")
                benign_info["context_notes"].append(
                    "Large overlay, high entropy, and registry APIs are EXPECTED for installers"
                )
            version = self.results.get("version_info", {})
            if version.get("has_version_info"):
                if not version.get("filename_mismatch"):
                    score += 5
                    benign_info["evidence"].append("Version info consistent with filename")
                company = str(version.get("company_name", "")).lower()
                trusted_companies = ['microsoft', 'google', 'adobe', 'valve', 'nvidia',
                                    'intel', 'amd', 'mozilla', 'apple', 'oracle', 'steam']
                for tc in trusted_companies:
                    if tc in company:
                        score += 10
                        benign_info["evidence"].append(f"Known software vendor: {version.get('company_name')}")
                        break
            pe = self.results.get("pe_analysis", {})
            sections = pe.get("sections", [])
            if sections:
                section_names = [s.get("name", "") for s in sections]
                non_standard = [s for s in section_names if s not in self.STANDARD_SECTIONS]
                if not non_standard:
                    score += 5
                    benign_info["evidence"].append("Standard PE section layout")
            strings_data = self.results.get("strings", {})
            all_strings = str(strings_data)
            persistence_targets = [
                'CurrentVersion\\Run', 'CurrentVersion\\RunOnce',
                'schtasks', 'at.exe', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
            ]
            has_persistence_target = any(pt.lower() in all_strings.lower() for pt in persistence_targets)
            if not has_persistence_target:
                score += 8
                benign_info["evidence"].append("No persistence mechanism registry keys found")
            urls = strings_data.get("urls", [])
            suspicious_urls = []
            for url in urls:
                url_lower = url.lower()
                is_whitelisted = any(domain in url_lower for domain in self.INSTALLER_WHITELIST_URLS)
                if not is_whitelisted and 'http' in url_lower:
                    if not any(safe in url_lower for safe in ['.microsoft.com', '.google.com', 'localhost']):
                        suspicious_urls.append(url)
            if urls and not suspicious_urls:
                score += 5
                benign_info["evidence"].append("All URLs appear to be from legitimate sources")
            benign_info["benign_score"] = score
            self.results["benign_indicators"] = benign_info
            logger.info(f"Benign indicators calculated: score={score}")
        except Exception as e:
            logger.error(f"Error calculating benign indicators: {e}")
            self.results["benign_indicators"] = {"benign_score": 0, "error": str(e)}
    def detect_malware_indicators(self):
        try:
            indicators = {
                "hard_indicators": [],
                "hard_indicator_score": 0,
                "malware_strings": [],
                "suspicious_urls": [],
                "suspicious_ips": [],
                "c2_indicators": [],
                "ransomware_indicators": [],
                "evasion_indicators": [],
                "structural_indicators": []
            }
            score = 0
            strings_data = self.results.get("strings", {})
            interesting_strings = strings_data.get("interesting_strings", [])
            all_urls = strings_data.get("urls", [])
            all_ips = strings_data.get("ip_addresses", [])
            crypto_strings = strings_data.get("crypto_payment", [])
            api_calls = strings_data.get("api_calls", [])
            registry_keys = strings_data.get("registry_keys", [])
            all_string_content = " ".join(interesting_strings + all_urls + crypto_strings)
            if interesting_strings:
                string_score = min(len(interesting_strings) * 3, 30)
                score += string_score
                indicators["malware_strings"].append(f"{len(interesting_strings)} suspicious strings: +{string_score}")
                indicators["hard_indicators"].append(f"Suspicious strings: {len(interesting_strings)} found")
                high_value = ["ransom", "encrypt", "decrypt", "bitcoin", "wallet", "backdoor",
                             "keylog", "inject", "hook", "payload", "exploit"]
                for s in interesting_strings[:20]:
                    s_lower = s.lower()
                    for hv in high_value:
                        if hv in s_lower:
                            score += 5
                            indicators["ransomware_indicators"].append(f"'{hv}' in string")
                            break
            if all_urls:
                suspicious_tlds = ['.onion', '.bit', '.bazar', '.tk', '.ml', '.ga', '.cf', '.xyz']
                c2_patterns = ['/gate.php', '/panel.php', '/c2/', '/bot/', '/cmd/', '/admin.php',
                              'pastebin.com/raw', 'paste.ee', 'hastebin.com']
                for url in all_urls:
                    url_lower = url.lower()
                    for tld in suspicious_tlds:
                        if tld in url_lower:
                            score += 15
                            indicators["suspicious_urls"].append(f"{url[:60]} (TLD: {tld})")
                            indicators["hard_indicators"].append(f"Suspicious URL: {url[:40]}")
                            break
                    for pattern in c2_patterns:
                        if pattern in url_lower:
                            score += 20
                            indicators["c2_indicators"].append(url[:60])
                            indicators["hard_indicators"].append(f"C2 pattern in URL: {pattern}")
                            break
            import re
            external_ip_count = 0
            for ip_str in all_ips:
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', ip_str)
                if ip_match:
                    ip = ip_match.group(1)
                    octets = [int(x) for x in ip.split('.') if x.isdigit()]
                    if len(octets) == 4:
                        o1, o2 = octets[0], octets[1]
                        is_private = (o1 == 10 or o1 == 127 or o1 == 0 or o1 == 255 or
                                     (o1 == 172 and 16 <= o2 <= 31) or
                                     (o1 == 192 and o2 == 168))
                        if not is_private and external_ip_count < 5:
                            score += 8
                            external_ip_count += 1
                            indicators["suspicious_ips"].append(ip)
                            indicators["hard_indicators"].append(f"External IP: {ip}")
            version_info = self.results.get("version_info", {})
            authenticode = self.results.get("authenticode", {})
            entropy_data = self.results.get("entropy", {})
            installer_info = self.results.get("installer_info", {})
            has_version = version_info.get("has_version_info", False)
            is_signed = authenticode.get("is_signed", False)
            is_installer = installer_info.get("is_installer", False)
            file_entropy = entropy_data.get("file_entropy", 0)
            if not is_installer:
                if not is_signed and not has_version:
                    score += 20
                    indicators["structural_indicators"].append("Unsigned + no version info: +20")
                    indicators["hard_indicators"].append("No signature and no version info")
                elif not is_signed:
                    score += 8
                    indicators["structural_indicators"].append("Unsigned binary: +8")
                    indicators["hard_indicators"].append("Unsigned binary")
            if file_entropy > 7.5 and not is_installer:
                score += 10
                indicators["structural_indicators"].append(f"High entropy ({file_entropy:.2f}): +10")
                indicators["hard_indicators"].append(f"High entropy: {file_entropy:.2f}")
            company = str(version_info.get("company_name", "")).lower()
            if company and not is_signed:
                fake_companies = ["microsoft", "google", "adobe", "apple"]
                for fc in fake_companies:
                    if fc in company:
                        score += 25
                        indicators["structural_indicators"].append(f"Fake version info (claims {fc}): +25")
                        indicators["hard_indicators"].append(f"Claims to be {fc} but unsigned")
                        break
            anti_analysis = self.results.get("anti_analysis", {})
            anti_techniques = anti_analysis.get("techniques_detected", [])
            if len(anti_techniques) >= 3:
                points = min(5 + (len(anti_techniques) - 2) * 4, 30)
                score += points
                indicators["evasion_indicators"].append(f"{len(anti_techniques)} anti-analysis: +{points}")
                indicators["hard_indicators"].append(f"Anti-analysis: {len(anti_techniques)} techniques")
            inst_debug = self.results.get("instruction_anti_debug", {})
            if not inst_debug.get("skipped", True):
                techniques = inst_debug.get("techniques_found", [])
                if techniques:
                    points = min(len(techniques) * 5, 25)
                    score += points
                    indicators["evasion_indicators"].append(f"Instruction anti-debug: +{points}")
                    indicators["hard_indicators"].append(f"Anti-debug instructions: {len(techniques)}")
            cap = self.results.get("capability_mapping", {})
            detected_behaviors = cap.get("detected_behaviors", [])
            high_risk_caps = {
                "process_injection": 35,
                "credential_theft": 40,
                "ransomware_behavior": 45,
                "keylogging": 30,
                "file_destruction": 25,
                "process_termination": 20,
                "privilege_escalation": 25,
                "file_enumeration": 10
            }
            for behavior, points in high_risk_caps.items():
                if behavior in detected_behaviors:
                    if behavior == "file_enumeration":
                        if "ransomware_behavior" in detected_behaviors or "file_destruction" in detected_behaviors:
                            score += points
                            indicators["hard_indicators"].append(f"Capability: {behavior}")
                    else:
                        score += points
                        conf = cap.get("confidence_levels", {}).get(behavior, "low")
                        indicators["hard_indicators"].append(f"Capability: {behavior} ({conf})")
            tls = self.results.get("tls_callbacks", {})
            if tls.get("callbacks") and len(tls.get("callbacks", [])) > 0:
                score += 15
                indicators["structural_indicators"].append("TLS callbacks (pre-entry): +15")
                indicators["hard_indicators"].append(f"TLS callbacks: {len(tls.get('callbacks', []))}")
            yara = self.results.get("yara_matches", {})
            yara_matches = yara.get("matches", [])
            malware_families = yara.get("malware_families", [])
            if yara_matches:
                base_yara = 20
                family_bonus = len(malware_families) * 20
                match_bonus = min((len(yara_matches) - 1) * 8, 30)
                total_yara = base_yara + family_bonus + match_bonus
                score += total_yara
                indicators["hard_indicators"].append(f"YARA: {len(yara_matches)} matches, {len(malware_families)} families (+{total_yara})")
            import_cats = self.results.get("import_categories", {}).get("categories", {})
            injection_count = import_cats.get("injection", {}).get("count", 0)
            network_count = import_cats.get("network", {}).get("count", 0)
            crypto_count = import_cats.get("crypto", {}).get("count", 0)
            if crypto_count >= 2:
                if "file_enumeration" in detected_behaviors:
                    score += 20
                    indicators["hard_indicators"].append("Crypto APIs + file enumeration (ransomware pattern)")
            if network_count >= 2 and injection_count >= 1:
                score += 15
                indicators["hard_indicators"].append("Network + injection APIs (RAT pattern)")
            indicators["hard_indicator_score"] = score
            self.results["malware_indicators"] = indicators
            logger.info(f"Malware indicators detected: score={score}, hard_indicators={len(indicators['hard_indicators'])}")
        except Exception as e:
            logger.error(f"Error detecting malware indicators: {e}")
            import traceback
            traceback.print_exc()
            self.results["malware_indicators"] = {"hard_indicator_score": 0, "error": str(e)}
    def detect_contradictions(self):
        try:
            contradictions = []
            role = self.results.get("file_role", {}).get("role", "unknown")
            auth = self.results.get("authenticode", {})
            version = self.results.get("version_info", {})
            entropy_info = self.results.get("entropy", {})
            packer = self.results.get("packer_detection", {})
            api_clusters = self.results.get("api_clusters", {})
            capabilities = self.results.get("capability_mapping", {})
            strings = self.results.get("strings", {})
            file_size = self.results.get("metadata", {}).get("file_size", 0)
            overlay = self.results.get("overlay", {})
            if role == "installer":
                if not version.get("has_version_info") and not auth.get("is_signed"):
                    contradictions.append({
                        "type": "installer_no_identity",
                        "description": "Claims to be installer but has no version info AND no signature",
                        "weight": 30,
                        "explanation": "Legitimate installers always have version info or signatures for trust"
                    })
            company = str(version.get("company_name", "")).lower()
            is_trusted_vendor = auth.get("is_signed") and any(v in company for v in ['microsoft', 'google', 'adobe', 'mozilla', 'apple', 'valve'])
            if role in ["application", "installer"] and not is_trusted_vendor:
                clusters = api_clusters.get("clusters_detected", [])
                injection_clusters = [c for c in clusters if c["cluster"] in ["injection", "hollow_process"]]
                if injection_clusters and not self.results.get("admin_tool_detection", {}).get("is_admin_tool"):
                    contradictions.append({
                        "type": "app_with_injection",
                        "description": f"Normal {role} detected with process injection capability",
                        "weight": 40,
                        "explanation": f"Detected: {', '.join([c['intent'] for c in injection_clusters])}"
                    })
            if auth.get("is_signed"):
                malicious_weight = api_clusters.get("total_malicious_weight", 0)
                if malicious_weight >= 70:
                    contradictions.append({
                        "type": "signed_malicious",
                        "description": "Signed binary but has high-confidence malicious API patterns",
                        "weight": 35,
                        "explanation": f"Signature does not guarantee safety - malicious weight: {malicious_weight}"
                    })
            if file_size < 100000:
                has_network = "network_communication" in capabilities.get("detected_behaviors", [])
                crypto_payment = strings.get("crypto_payment", [])
                if has_network and crypto_payment:
                    contradictions.append({
                        "type": "small_ransomware_pattern",
                        "description": "Small file with network capability and cryptocurrency references",
                        "weight": 45,
                        "explanation": "Classic ransomware/downloader pattern"
                    })
            if role == "application":
                imports_count = self.results.get("imports_exports", {}).get("total_imports", 0)
                if imports_count < 20 and packer.get("likely_packed"):
                    contradictions.append({
                        "type": "hollowed_tool",
                        "description": "Claims to be application but has minimal imports and is packed",
                        "weight": 25,
                        "explanation": "Legitimate apps have many imports; packed+minimal suggests loader"
                    })
            company = str(version.get("company_name", "")).lower()
            trusted_companies = ['microsoft', 'google', 'adobe', 'oracle', 'mozilla', 'apple']
            is_system_tool_local = self.is_windows_system_tool()
            if any(tc in company for tc in trusted_companies):
                if not auth.get("is_signed"):
                    weight = 15 if is_system_tool_local else 35
                    contradictions.append({
                        "type": "fake_vendor",
                        "description": f"Claims to be from {company} but is unsigned" + (" (system tool)" if is_system_tool_local else ""),
                        "weight": weight,
                        "explanation": "Major vendors always sign their binaries"
                    })
            file_entropy = entropy_info.get("file_entropy", 0)
            if file_entropy > 7.8 and role != "installer":
                contradictions.append({
                    "type": "extreme_entropy",
                    "description": "Extreme file entropy suggests heavy encryption/packing",
                    "weight": 20,
                    "explanation": f"File entropy: {file_entropy:.2f} (normal: 5-7, packed: 7-8)"
                })
            self.results["contradictions"] = {
                "detected": contradictions,
                "count": len(contradictions),
                "total_weight": sum(c["weight"] for c in contradictions),
                "has_contradictions": len(contradictions) > 0
            }
            logger.info(f"Contradiction detection: {len(contradictions)} contradictions found")
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error detecting contradictions: {e}")
            self.results["contradictions"] = {"detected": [], "count": 0, "error": str(e)}
    def calculate_risk_score(self):
        try:
            role = self.results.get("file_role", {}).get("role", "unknown")
            is_installer = role == "installer"
            is_admin_tool = self.results.get("admin_tool_detection", {}).get("is_admin_tool", False)
            is_system_tool = self.is_windows_system_tool()
            risk_score = {
                "score": 0,
                "verdict": "Unknown",
                "indicators": [],
                "contradictions": [],
                "trust_adjustments": [],
                "baseline_indicators": [],
                "breakdown": {},
                "analysis_context": "Hybrid scoring (baseline + contradiction-based)",
                "scoring_model": "v3.0_hybrid"
            }
            baseline_score = 0
            auth = self.results.get("authenticode", {})
            version = self.results.get("version_info", {})
            is_signed = auth.get("is_signed", False)
            has_version = version.get("has_version_info", False)
            if not is_signed and not has_version:
                if role == "unknown":
                    baseline_score += 25
                    risk_score["baseline_indicators"].append("No signature + no version info (unknown role): +25")
                elif not is_installer:
                    baseline_score += 15
                    risk_score["baseline_indicators"].append("No signature + no version info: +15")
            is_pe = self.results.get("pe_analysis", {}).get("is_pe_file", False)
            file_size = self.results.get("metadata", {}).get("file_size", 0)
            total_imports = self.results.get("imports_exports", {}).get("total_imports", 0)
            if is_pe and file_size < 50000 and total_imports < 15:
                baseline_score += 15
                risk_score["baseline_indicators"].append(f"Small PE ({file_size} bytes) + few imports ({total_imports}): +15")
            elif is_pe and total_imports < 10:
                baseline_score += 10
                risk_score["baseline_indicators"].append(f"Minimal imports ({total_imports}): +10")
            entropy = self.results.get("entropy", {}).get("file_entropy", 0)
            if entropy > 7.2:
                baseline_score += 10
                risk_score["baseline_indicators"].append(f"High entropy ({entropy:.2f}): +10")
            packer = self.results.get("packer_detection", {})
            if packer.get("likely_packed") and not is_installer:
                baseline_score += 10
                risk_score["baseline_indicators"].append("Packer detected: +10")
            total_score = baseline_score
            imports = self.results.get("imports_exports", {}).get("imports", {})
            all_apis = set()
            for dll, funcs in imports.items():
                for func in funcs:
                    if isinstance(func, dict):
                        all_apis.add(func.get("name", ""))
                    else:
                        all_apis.add(str(func))
            crypto_apis = {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
                          "CryptAcquireContextW", "CryptAcquireContextA",
                          "BCryptEncrypt", "BCryptDecrypt", "CryptImportKey", "CryptDeriveKey",
                          "CryptGenRandom", "BCryptGenRandom"}
            file_enum_apis = {"FindFirstFile", "FindFirstFileW", "FindFirstFileA",
                             "FindNextFile", "FindNextFileW", "FindNextFileA"}
            file_mod_apis = {"WriteFile", "WriteFileEx", "MoveFile", "MoveFileW", "MoveFileA",
                            "MoveFileEx", "MoveFileExW", "DeleteFile", "DeleteFileW", "DeleteFileA",
                            "SetFileAttributes", "SetFileAttributesW"}
            loader_apis = {"CreateProcess", "CreateProcessW", "CreateProcessA",
                          "WinExec", "ShellExecute", "ShellExecuteW", "ShellExecuteA",
                          "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"}
            download_apis = {"URLDownloadToFile", "URLDownloadToFileW", "URLDownloadToFileA",
                            "InternetReadFile", "WinHttpReadData", "HttpSendRequest"}
            has_crypto = bool(all_apis & crypto_apis)
            has_file_enum = bool(all_apis & file_enum_apis)
            has_file_mod = bool(all_apis & file_mod_apis)
            has_loader = bool(all_apis & loader_apis)
            has_download = bool(all_apis & download_apis)
            screen_lock_apis = {"SetWindowsHookEx", "SetWindowsHookExW", "SetWindowsHookExA",
                               "BlockInput", "ShowWindow", "SetForegroundWindow",
                               "GetDesktopWindow", "SetWindowPos", "SystemParametersInfo",
                               "SystemParametersInfoW", "ExitWindowsEx", "LockWorkStation"}
            has_screen_lock = bool(all_apis & screen_lock_apis)
            persist_apis = {"RegSetValueEx", "RegSetValueExW", "RegSetValueExA",
                           "RegCreateKeyEx", "RegCreateKeyExW", "CreateService",
                           "CreateServiceW", "WritePrivateProfileString"}
            has_persist = bool(all_apis & persist_apis)
            CRYPTO_SYSTEM_TOOLS = {'cipher.exe', 'certutil.exe', 'certreq.exe', 'dpapi.exe'}
            current_filename = self.malware_path.name.lower()
            if has_crypto and has_file_enum and current_filename not in CRYPTO_SYSTEM_TOOLS:
                locker_score = 30
                if has_file_mod:
                    locker_score += 15
                if not is_signed and role == "unknown":
                    locker_score += 10
                total_score += locker_score
                risk_score["indicators"].append(f"LOCKER PATTERN (crypto+file_enum): +{locker_score}")
            if has_screen_lock and role == "unknown" and not is_signed:
                screen_score = 25
                if has_persist:
                    screen_score += 15
                total_score += screen_score
                risk_score["indicators"].append(f"SCREEN LOCKER PATTERN (window hooks/lockout): +{screen_score}")
            if file_size < 100000 and role == "unknown":
                if has_loader and has_download:
                    total_score += 35
                    risk_score["indicators"].append("LOADER PATTERN (process+download, small file): +35")
                elif has_download and not is_signed:
                    total_score += 25
                    risk_score["indicators"].append("DROPPER PATTERN (download, small unsigned): +25")
                elif has_loader and "VirtualAllocEx" in all_apis and "WriteProcessMemory" in all_apis:
                    total_score += 40
                    risk_score["indicators"].append("INJECTION LOADER (VirtualAllocEx+WriteProcessMemory): +40")
                elif "VirtualAllocEx" in all_apis and not is_signed:
                    total_score += 20
                    risk_score["indicators"].append("SUSPICIOUS ALLOC (VirtualAllocEx, small unsigned): +20")
            if is_pe and file_size < 50000 and not is_signed and role == "unknown":
                suspicious_api_count = sum([has_crypto, has_file_enum, has_file_mod,
                                           has_loader, has_download, has_screen_lock, has_persist])
                if suspicious_api_count >= 2:
                    escalation = 20
                    total_score += escalation
                    risk_score["indicators"].append(f"MINIMAL MALWARE (small+unsigned+{suspicious_api_count} suspicious APIs): +{escalation}")
                elif suspicious_api_count == 1 and has_persist:
                    total_score += 15
                    risk_score["indicators"].append("MINIMAL MALWARE (small+unsigned+persistence): +15")
            contradictions = self.results.get("contradictions", {}).get("detected", [])
            has_contradictions = len(contradictions) > 0
            for c in contradictions:
                total_score += c["weight"]
                risk_score["contradictions"].append(f"{c['description']}: +{c['weight']}")
                risk_score["indicators"].append(f"CONTRADICTION: {c['type']} (+{c['weight']})")
            api_clusters = self.results.get("api_clusters", {})
            cluster_weight = api_clusters.get("total_malicious_weight", 0)
            if cluster_weight > 0 and not is_admin_tool:
                total_score += cluster_weight
                risk_score["indicators"].append(f"Malicious API clusters: +{cluster_weight}")
            yara = self.results.get("yara_matches", {})
            yara_count = len(yara.get("matches", []))
            families = len(yara.get("malware_families", []))
            if yara_count > 0:
                yara_score = 25 + (yara_count - 1) * 10 + families * 20
                total_score += yara_score
                risk_score["indicators"].append(f"YARA matches ({yara_count}, {families} families): +{yara_score}")
            elif role == "unknown":
                risk_score["trust_adjustments"].append("No YARA matches: reduced malware confidence")
            if has_contradictions:
                tls = self.results.get("tls_callbacks", {})
                tls_count = len(tls.get("callbacks", []))
                if tls_count > 0:
                    total_score += 15
                    risk_score["indicators"].append(f"TLS callbacks ({tls_count}): +15")
                anti = self.results.get("anti_analysis", {})
                anti_count = len(anti.get("techniques_detected", []))
                if anti_count >= 3:
                    score = min(anti_count * 5, 25)
                    total_score += score
                    risk_score["indicators"].append(f"Anti-analysis ({anti_count}): +{score}")
                strings = self.results.get("strings", {})
                crypto_payment = strings.get("crypto_payment", [])
                if crypto_payment:
                    score = min(len(crypto_payment) * 10, 30)
                    risk_score["indicators"].append(f"Cryptocurrency references ({len(crypto_payment)}): +{score}")
            vt = self.results.get("threat_intel", {}).get("virustotal", {})
            vt_positives = vt.get("positives", 0)
            vt_total = vt.get("total", 1) or 1
            vt_detection_rate = vt_positives / vt_total
            vt_trust_revoked = False
            if vt.get("detected") and vt_positives > 10:
                if vt_positives > 30:
                    vt_boost = min(int(vt_positives * 0.7), 50)
                else:
                    vt_boost = min(vt_positives, 30)
                total_score += vt_boost
                risk_score["indicators"].append(f"VirusTotal {vt_positives}/{vt_total} detections: +{vt_boost}")
                if vt_detection_rate > 0.5 and is_signed:
                    vt_trust_revoked = True
                    risk_score["trust_adjustments"].append("VT >50% detection - trust revoked for signed file")
            auth = self.results.get("authenticode", {})
            is_signed = auth.get("is_signed", False)
            signer = str(auth.get("signer", "")).lower()
            if not has_contradictions and not vt_trust_revoked:
                TRUST_TIERS = {
                    "microsoft": -40, "oracle": -40, "google": -40, "adobe": -30,
                    "valve": -25, "nvidia": -25, "intel": -25, "mozilla": -25
                }
                for vendor, reduction in TRUST_TIERS.items():
                    if vendor in signer:
                        total_score = max(0, total_score + reduction)
                        risk_score["trust_adjustments"].append(f"Trusted vendor ({vendor}): {reduction}")
                        break
                else:
                    if is_signed:
                        total_score = max(0, total_score - 20)
                        risk_score["trust_adjustments"].append("Valid signature (unknown vendor): -20")
                if is_installer:
                    framework = self.results.get("installer_info", {}).get("framework", "Unknown")
                    confidence = self.results.get("installer_info", {}).get("confidence", 0)
                    if confidence > 0.7:
                        reduction = min(total_score, 30)
                        total_score = max(0, total_score - reduction)
                        risk_score["trust_adjustments"].append(f"Installer ({framework}): -{reduction}")
            else:
                risk_score["trust_adjustments"].append("Trust tiers DISABLED due to contradictions")
                if is_installer and not is_signed:
                    total_score += 25
                    risk_score["indicators"].append("Unsigned installer WITH contradictions: +25")
            if is_system_tool and not has_contradictions:
                reduction = min(total_score, 45)
                total_score = max(0, total_score - reduction)
                risk_score["trust_adjustments"].append(f"Windows system tool: -{reduction}")
            total_score = min(total_score, 100)
            risk_score["score"] = total_score
            risk_score["breakdown"] = {
                "contradiction_weight": sum(c["weight"] for c in contradictions),
                "api_cluster_weight": cluster_weight,
                "trust_adjustments": total_score - sum(c["weight"] for c in contradictions) - cluster_weight,
                "final": total_score
            }
            if total_score >= 70:
                risk_score["verdict"] = "Malicious" if has_contradictions else "High Risk"
            elif total_score >= 50:
                risk_score["verdict"] = "High Risk" if has_contradictions else "Suspicious"
            elif total_score >= 30:
                risk_score["verdict"] = "Medium Risk"
            elif total_score >= 15:
                risk_score["verdict"] = "Low Risk"
            elif total_score > 0:
                risk_score["verdict"] = "Minimal Risk"
            else:
                if is_installer or is_admin_tool or is_system_tool:
                    risk_score["verdict"] = "Clean"
                else:
                    risk_score["verdict"] = "Unrated"
            self.results["risk_score"] = risk_score
            logger.info(f"RISK SCORE: {total_score} - {risk_score['verdict']} "
                       f"(contradictions: {len(contradictions)}, indicators: {len(risk_score['indicators'])})")
        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            import traceback
            traceback.print_exc()
            self.results["risk_score"] = {"score": 0, "verdict": "Error", "error": str(e)}
    def human_readable_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    def generate_suspicion_report(self):
        try:
            report = {
                "suspicious_dlls": [],
                "suspicious_apis": [],
                "suspicious_behaviors": [],
                "suspicious_characteristics": [],
                "analyst_notes": []
            }
            dll_explanations = {
                "ntdll.dll": "Direct NT API access - bypasses Win32 API monitoring, common in malware",
                "ws2_32.dll": "Winsock networking - enables C2 communication, data exfiltration",
                "wininet.dll": "Internet functions - HTTP/FTP communication for C2 or downloads",
                "winhttp.dll": "HTTP client - often used for stealthy web-based C2",
                "crypt32.dll": "Cryptographic functions - encryption for ransomware or secure C2",
                "advapi32.dll": "Advanced API - registry, services, security tokens manipulation",
                "psapi.dll": "Process status API - process enumeration for injection targets",
                "dbghelp.dll": "Debug helper - symbol handling, can be used for anti-debugging",
                "kernel32.dll": "Core API - normal but watch for VirtualAlloc/WriteProcessMemory",
                "urlmon.dll": "URL moniker - file downloads, often malware dropper indicator",
                "mscoree.dll": ".NET runtime - possible .NET malware or loader",
                "vaultcli.dll": "Credential vault - credential theft indicator",
                "samlib.dll": "SAM library - password hash extraction"
            }
            imports = self.results.get("imports_exports", {}).get("imports", {})
            for dll_name in imports.keys():
                dll_lower = dll_name.lower()
                for sus_dll, explanation in dll_explanations.items():
                    if sus_dll in dll_lower:
                        report["suspicious_dlls"].append({
                            "dll": dll_name,
                            "why_suspicious": explanation,
                            "imported_functions": len(imports.get(dll_name, []))
                        })
            api_explanations = {
                "VirtualAllocEx": "Allocates memory in ANOTHER process - required for code injection",
                "WriteProcessMemory": "Writes to another process memory - shellcode injection",
                "CreateRemoteThread": "Creates thread in another process - classic injection technique",
                "NtCreateThreadEx": "Low-level thread creation - stealthier injection",
                "QueueUserAPC": "APC injection - early-bird or atom bombing attacks",
                "SetThreadContext": "Modifies thread context - used in process hollowing",
                "NtUnmapViewOfSection": "Unmaps section - process hollowing preparation",
                "GetAsyncKeyState": "Checks key state - keylogger indicator",
                "GetKeyState": "Gets key status - input monitoring",
                "GetKeyboardState": "Gets full keyboard state - comprehensive keylogging",
                "SetWindowsHookEx": "Installs hook - keyboard/mouse interception",
                "GetClipboardData": "Reads clipboard - password/data theft",
                "GetRawInputData": "Raw input access - stealthy keylogging",
                "CredEnumerate": "Enumerates stored credentials - password theft",
                "CredRead": "Reads stored credentials - direct credential access",
                "CryptUnprotectData": "Decrypts DPAPI data - browser password extraction",
                "LsaRetrievePrivateData": "LSA secrets access - domain credential theft",
                "IsDebuggerPresent": "Debugger detection - anti-analysis",
                "CheckRemoteDebuggerPresent": "Remote debugger check - anti-analysis",
                "NtQueryInformationProcess": "Process info query - debugger/VM detection",
                "GetTickCount": "Timing check - sandbox detection via timing attacks",
                "QueryPerformanceCounter": "High-res timing - timing-based evasion",
                "Sleep": "Execution delay - sandbox timeout evasion",
                "RegSetValueEx": "Registry write - potential persistence mechanism",
                "RegCreateKeyEx": "Registry key creation - autorun persistence",
                "CreateService": "Service creation - service-based persistence",
                "AdjustTokenPrivileges": "Token privilege adjustment - privilege escalation",
                "OpenProcessToken": "Opens process token - privilege manipulation",
                "ImpersonateLoggedOnUser": "User impersonation - privilege abuse",
                "InternetOpen": "Internet connection init - C2 communication setup",
                "HttpOpenRequest": "HTTP request - web-based C2",
                "URLDownloadToFile": "File download - dropper/downloader behavior",
                "WSAStartup": "Winsock init - raw network communication"
            }
            for dll_name, funcs in imports.items():
                for func in funcs:
                    func_name = func.get("name", "")
                    for api, explanation in api_explanations.items():
                        if api.lower() == func_name.lower() or api.lower() in func_name.lower():
                            report["suspicious_apis"].append({
                                "api": func_name,
                                "dll": dll_name,
                                "why_suspicious": explanation
                            })
                            break
            behavior_explanations = {
                "keylogging": "Captures keystrokes - used to steal passwords, sensitive data, and monitor user activity",
                "screen_capture": "Takes screenshots - information theft, espionage, or monitoring victim activity",
                "clipboard_access": "Monitors clipboard - steals copied passwords, crypto addresses, sensitive text",
                "process_injection": "Injects code into other processes - evades detection, gains privileges, persists",
                "credential_theft": "Extracts stored credentials - enables lateral movement, account takeover",
                "anti_debug": "Detects debugging - hinders malware analysis, indicates malicious intent",
                "timing_evasion": "Uses timing checks - evades sandbox analysis by detecting artificial environments",
                "network_communication": "Network capabilities - C2 communication, data exfiltration, payload download",
                "persistence": "Establishes persistence - survives reboots, maintains long-term access",
                "privilege_escalation": "Elevates privileges - gains admin/SYSTEM access for deeper compromise",
                "dll_loading": "Dynamic DLL loading - loads additional malicious code, evades static detection"
            }
            cap = self.results.get("capability_mapping", {})
            for behavior in cap.get("detected_behaviors", []):
                if behavior in behavior_explanations:
                    apis = cap.get("behavior_details", {}).get(behavior, {})
                    if isinstance(apis, dict):
                        api_list = apis.get("apis", [])
                    else:
                        api_list = apis
                    report["suspicious_behaviors"].append({
                        "behavior": behavior,
                        "why_suspicious": behavior_explanations[behavior],
                        "evidence_apis": api_list[:5]
                    })
            if self.results.get("overlay", {}).get("has_overlay"):
                overlay = self.results.get("overlay", {})
                ratio = overlay.get("overlay_ratio", 0)
                if ratio > 50:
                    report["suspicious_characteristics"].append({
                        "characteristic": f"Large overlay ({ratio}% of file)",
                        "why_suspicious": "Embedded payload or encrypted second-stage malware hidden after PE structure"
                    })
                elif overlay.get("suspicious"):
                    report["suspicious_characteristics"].append({
                        "characteristic": "Suspicious overlay data",
                        "why_suspicious": "High entropy overlay may contain encrypted payload or configuration"
                    })
            if self.results.get("tls_callbacks", {}).get("callbacks"):
                count = len(self.results.get("tls_callbacks", {}).get("callbacks", []))
                report["suspicious_characteristics"].append({
                    "characteristic": f"{count} TLS callback(s)",
                    "why_suspicious": "Code runs BEFORE entry point - evades debuggers that break on EP"
                })
            if not self.results.get("authenticode", {}).get("is_signed"):
                report["suspicious_characteristics"].append({
                    "characteristic": "Unsigned binary",
                    "why_suspicious": "No code signing - cannot verify publisher, easier to modify/distribute"
                })
            if self.results.get("version_info", {}).get("filename_mismatch"):
                report["suspicious_characteristics"].append({
                    "characteristic": "Filename mismatch",
                    "why_suspicious": "Masquerading - file pretends to be different software to evade detection"
                })
            if self.results.get("config_detection", {}).get("xor_patterns"):
                report["suspicious_characteristics"].append({
                    "characteristic": "XOR-encrypted data detected",
                    "why_suspicious": "Encrypted configuration or payload - hides C2 servers, keys"
                })
            if len(self.results.get("anti_analysis", {}).get("techniques_detected", [])) >= 5:
                report["suspicious_characteristics"].append({
                    "characteristic": "Heavy anti-analysis (5+ techniques)",
                    "why_suspicious": "Significant effort to evade analysis - strong malware indicator"
                })
            score = self.results.get("risk_score", {}).get("score", 0)
            verdict = self.results.get("risk_score", {}).get("verdict", "Unknown")
            if score >= 50:
                report["analyst_notes"].append(
                    f"⚠️ HIGH RISK SAMPLE: Score {score} indicates multiple malicious indicators. "
                    "This sample exhibits behaviors consistent with malware. Recommend extreme caution "
                    "and isolation before allowing in any environment."
                )
            elif score >= 25:
                report["analyst_notes"].append(
                    f"⚡ MEDIUM RISK: Score {score} shows concerning indicators. "
                    "Could be potentially unwanted program (PUP) or early-stage malware. "
                    "Further advanced analysis recommended."
                )
            self.results["why_suspicious"] = report
            logger.info(f"Suspicion report generated: {len(report['suspicious_apis'])} APIs, {len(report['suspicious_behaviors'])} behaviors")
        except Exception as e:
            logger.error(f"Error generating suspicion report: {e}")
            self.results["why_suspicious"] = {"error": str(e)}
def main():
    parser = argparse.ArgumentParser(description='AWS-based Automated Malware Static Analysis')
    parser.add_argument('malware_sample', help='Path to malware sample')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--output-format', choices=['json'], default='json',
                       help='Output format for analysis report (JSON only)')
    parser.add_argument('--local', action='store_true', help='Run analysis locally without AWS')
    parser.add_argument('--output-file', default=None, help='Specific output file path')
    args = parser.parse_args()
    if not os.path.exists(args.malware_sample):
        logger.error(f"Malware sample not found: {args.malware_sample}")
        sys.exit(1)
    try:
        config = {}
        if os.path.exists(args.config):
            try:
                with open(args.config, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded config from {args.config}")
            except Exception as e:
                logger.warning(f"Could not load config: {e}")
        if args.local:
            logger.info("Running static analysis locally...")
            analyzer = StaticAnalyzer(args.malware_sample, config=config)
            results = analyzer.analyze_all()
            if args.output_file:
                output_path = args.output_file
            else:
                file_hash = results.get('hashes', {}).get('sha256', 'unknown')
                output_path = f"{file_hash}.json"
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Analysis results saved to {output_path}")
            try:
                parser_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parser.py')
                txt_report_name = output_path.replace('.json', '.txt')
                logger.info(f"Generating parsed text report: {txt_report_name}...")
                subprocess.run(['python3', parser_script, output_path, '-o', txt_report_name], check=True)
                logger.info("Text report generated successfully.")
            except Exception as pe:
                logger.error(f"Failed to automatically generate text report: {pe}")
        else:
            logger.info("Starting analysis...")
            analyzer = StaticAnalyzer(args.malware_sample, config=config)
            results = analyzer.analyze_all()
            if args.output_file:
                output_path = args.output_file
            else:
                file_hash = results.get('hashes', {}).get('sha256', 'unknown')
                output_path = f"{file_hash}.json"
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Analysis results saved to {output_path}")
            try:
                parser_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'parser.py')
                txt_report_name = output_path.replace('.json', '.txt')
                logger.info(f"Generating parsed text report: {txt_report_name}...")
                subprocess.run(['python3', parser_script, output_path, '-o', txt_report_name], check=True)
                logger.info("Text report generated successfully.")
            except Exception as pe:
                logger.error(f"Failed to automatically generate text report: {pe}")
            print("\n" + "=" * 80)
            print("ANALYSIS COMPLETE")
            print("=" * 80)
            print(f"SHA256: {results.get('hashes', {}).get('sha256', 'N/A')}")
            print(f"File Type: {results.get('metadata', {}).get('file_type', 'N/A')}")
            print(f"Entropy: {results.get('entropy', {}).get('file_entropy', 'N/A'):.4f}")
            if results.get('pe_analysis', {}).get('imphash'):
                print(f"ImpHash: {results['pe_analysis']['imphash']}")
            print(f"Packed: {results.get('packer_detection', {}).get('likely_packed', False)}")
            print(f"Anti-Analysis Techniques: {results.get('anti_analysis', {}).get('total_techniques', 0)}")
            print("=" * 80)
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)
if __name__ == "__main__":
    import binascii
    from math import log2
    main()