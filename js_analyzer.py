#!/usr/bin/env python3
"""
JS Analyzer Wrapper
Mengintegrasikan feroxbuster, LinkFinder, dan SecretFinder untuk analisis file JavaScript
"""

import os
import sys
import json
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
import time

# Inisialisasi colorama untuk output berwarna
init(autoreset=True)

class JSAnalyzer:
    def __init__(self, target_url, output_dir="results"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.js_files = []
        self.feroxbuster_path = self._find_feroxbuster()
        self.linkfinder_path = self._find_linkfinder()
        self.secretfinder_path = self._find_secretfinder()
        
        # Buat direktori output
        self.output_dir.mkdir(exist_ok=True)
        
    def _find_feroxbuster(self):
        """Mencari path feroxbuster"""
        try:
            result = subprocess.run(['which', 'feroxbuster'], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Coba cari di PATH
        for path in os.environ.get('PATH', '').split(':'):
            feroxbuster_path = os.path.join(path, 'feroxbuster')
            if os.path.exists(feroxbuster_path):
                return feroxbuster_path
                
        return None
    
    def _find_linkfinder(self):
        """Mencari path LinkFinder"""
        # Coba lokasi yang disediakan user
        linkfinder_path = Path("/Users/theninja/SF/LinkFinder/linkfinder.py")
        if linkfinder_path.exists():
            return str(linkfinder_path)
        
        # Coba cari di direktori saat ini
        linkfinder_path = Path("linkfinder.py")
        if linkfinder_path.exists():
            return str(linkfinder_path)
            
        # Coba cari di PATH
        for path in os.environ.get('PATH', '').split(':'):
            linkfinder_path = os.path.join(path, 'linkfinder.py')
            if os.path.exists(linkfinder_path):
                return linkfinder_path
                
        return None
    
    def _find_secretfinder(self):
        """Mencari path SecretFinder"""
        # Coba lokasi yang disediakan user
        secretfinder_path = Path("/Users/theninja/SF/secretfinder/SecretFinder.py")
        if secretfinder_path.exists():
            return str(secretfinder_path)
        
        # Coba cari di direktori saat ini
        secretfinder_path = Path("SecretFinder.py")
        if secretfinder_path.exists():
            return str(secretfinder_path)
            
        # Coba cari di PATH
        for path in os.environ.get('PATH', '').split(':'):
            secretfinder_path = os.path.join(path, 'SecretFinder.py')
            if os.path.exists(secretfinder_path):
                return secretfinder_path
                
        return None
    
    def print_banner(self):
        """Menampilkan banner aplikasi"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    JS Analyzer Wrapper v1.0                        ║
║  Integrates: Feroxbuster + LinkFinder + SecretFinder              ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def check_dependencies(self):
        """Memeriksa ketersediaan dependencies"""
        print(f"{Fore.YELLOW}[*] Memeriksa dependencies...{Style.RESET_ALL}")
        
        missing_deps = []
        
        if not self.feroxbuster_path:
            missing_deps.append("feroxbuster")
            print(f"{Fore.RED}[!] Feroxbuster tidak ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Feroxbuster ditemukan: {self.feroxbuster_path}{Style.RESET_ALL}")
        
        # LinkFinder dan SecretFinder sudah diintegrasikan dalam script ini
        print(f"{Fore.GREEN}[+] LinkFinder: Integrated dalam script{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] SecretFinder: Integrated dalam script{Style.RESET_ALL}")
        
        if missing_deps:
            print(f"\n{Fore.RED}[!] Dependencies yang hilang: {', '.join(missing_deps)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Silakan install dependencies yang hilang terlebih dahulu{Style.RESET_ALL}")
            return False
        
        return True
    
    def discover_js_files(self, wordlist=None, threads=50, timeout=10):
        """Menggunakan feroxbuster untuk menemukan file .js"""
        print(f"\n{Fore.CYAN}[*] Memulai discovery file .js menggunakan Feroxbuster...{Style.RESET_ALL}")
        
        if not self.feroxbuster_path:
            print(f"{Fore.RED}[!] Feroxbuster tidak tersedia{Style.RESET_ALL}")
            return False
        
        # Gunakan wordlist default jika tidak ada
        if not wordlist:
            default_wordlist = "/Users/theninja/SF/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
            if os.path.exists(default_wordlist):
                wordlist = default_wordlist
                print(f"{Fore.YELLOW}[*] Menggunakan wordlist default: {wordlist}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Wordlist harus disediakan dan wordlist default tidak ditemukan{Style.RESET_ALL}")
                return False
        
        # Command feroxbuster
        cmd = [
            self.feroxbuster_path,
            '--url', self.target_url,
            '--output', str(self.output_dir / 'feroxbuster_results.txt'),
            '--json',
            '-w', wordlist
        ]
        
        print(f"{Fore.YELLOW}[*] Command: {' '.join(cmd)}{Style.RESET_ALL}")
        
        try:
            print(f"{Fore.CYAN}[*] Menjalankan Feroxbuster...{Style.RESET_ALL}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Feroxbuster selesai{Style.RESET_ALL}")
                return self._parse_feroxbuster_results()
            else:
                print(f"{Fore.RED}[!] Feroxbuster error: {result.stderr}{Style.RESET_ALL}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] Feroxbuster timeout{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error menjalankan Feroxbuster: {e}{Style.RESET_ALL}")
            return False
    

    
    def _parse_feroxbuster_results(self):
        """Parse hasil feroxbuster"""
        results_file = self.output_dir / 'feroxbuster_results.txt'
        
        if not results_file.exists():
            print(f"{Fore.RED}[!] File hasil feroxbuster tidak ditemukan{Style.RESET_ALL}")
            return False
        
        js_files = []
        try:
            with open(results_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse JSON line dari feroxbuster
                    try:
                        data = json.loads(line)
                        
                        # Hanya ambil response type dan cek apakah file .js
                        if data.get('type') == 'response':
                            url = data.get('url', '')
                            if url and url.endswith('.js'):
                                js_files.append(url)
                                print(f"{Fore.CYAN}[+] Found JS: {url}{Style.RESET_ALL}")
                                
                    except json.JSONDecodeError:
                        # Skip non-JSON lines
                        continue
                        
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing hasil feroxbuster: {e}{Style.RESET_ALL}")
            return False
        
        self.js_files = list(set(js_files))  # Remove duplicates
        print(f"{Fore.GREEN}[+] Ditemukan {len(self.js_files)} file .js{Style.RESET_ALL}")
        
        # Simpan daftar file .js
        js_list_file = self.output_dir / 'js_files.txt'
        with open(js_list_file, 'w') as f:
            for js_file in self.js_files:
                f.write(f"{js_file}\n")
        
        return True
    
    def download_js_files(self):
        """Download semua file .js yang ditemukan"""
        if not self.js_files:
            print(f"{Fore.RED}[!] Tidak ada file .js untuk didownload{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.CYAN}[*] Downloading {len(self.js_files)} file .js...{Style.RESET_ALL}")
        
        js_dir = self.output_dir / "js_files"
        js_dir.mkdir(exist_ok=True)
        
        downloaded_files = []
        
        for js_url in tqdm(self.js_files, desc="Downloading JS files"):
            try:
                response = requests.get(js_url, timeout=30, verify=False)
                if response.status_code == 200:
                    # Buat nama file yang aman
                    parsed_url = urlparse(js_url)
                    filename = parsed_url.path.replace('/', '_').replace('\\', '_')
                    if not filename.endswith('.js'):
                        filename += '.js'
                    
                    file_path = js_dir / filename
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    
                    downloaded_files.append(str(file_path))
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Error downloading {js_url}: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Berhasil download {len(downloaded_files)} file{Style.RESET_ALL}")
        return downloaded_files
    
    def run_linkfinder(self, js_files):
        """Menjalankan LinkFinder pada file .js"""
        print(f"\n{Fore.CYAN}[*] Menjalankan LinkFinder...{Style.RESET_ALL}")
        
        linkfinder_results = []
        
        for js_file in tqdm(js_files, desc="Running LinkFinder"):
            try:
                output_file = self.output_dir / f"linkfinder_{Path(js_file).stem}.html"
                
                # Baca file JS
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Ekstrak endpoint menggunakan regex LinkFinder
                endpoints = self._extract_endpoints_from_js(content)
                
                # Buat HTML report
                html_content = self._create_linkfinder_html_report(js_file, endpoints)
                
                # Simpan file HTML
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                linkfinder_results.append({
                    'file': js_file,
                    'output': str(output_file)
                })
                print(f"{Fore.GREEN}[+] LinkFinder selesai untuk {js_file}{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Error menjalankan LinkFinder pada {js_file}: {e}{Style.RESET_ALL}")
        
        return linkfinder_results
    
    def _extract_endpoints_from_js(self, content):
        """Ekstrak endpoint dari JavaScript content menggunakan regex LinkFinder"""
        import re
        
        # Regex pattern dari LinkFinder
        regex_str = r"""
          (?:"|')                               # Start newline delimiter
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
            |
            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/.]{1,}                # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
            [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
            |
            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)        # . + extension
            (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
          )
          (?:"|')                               # End newline delimiter
        """
        
        matches = re.findall(regex_str, content, re.VERBOSE)
        endpoints = []
        
        for match in matches:
            for group in match:
                if group and len(group) > 3:  # Filter meaningful endpoints
                    endpoints.append(group)
        
        return list(set(endpoints))  # Remove duplicates
    
    def _create_linkfinder_html_report(self, js_file, endpoints):
        """Buat HTML report untuk LinkFinder"""
        file_name = Path(js_file).name
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>LinkFinder Results - {file_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .endpoint {{ background: #e8f4fd; padding: 8px 12px; margin: 4px 0; border-radius: 4px; border-left: 3px solid #3498db; }}
        .no-endpoints {{ color: #999; font-style: italic; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 LinkFinder Results</h1>
        <p><strong>File:</strong> {file_name}</p>
        <p><strong>Endpoints Found:</strong> {len(endpoints)}</p>
    </div>
    
    <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <h2>📋 Discovered Endpoints</h2>
"""
        
        if endpoints:
            for i, endpoint in enumerate(endpoints, 1):
                html_template += f'        <div class="endpoint">{i}. {endpoint}</div>\n'
        else:
            html_template += '        <div class="no-endpoints">No endpoints found</div>\n'
        
        html_template += """
    </div>
</body>
</html>
"""
        
        return html_template
    

    
    def run_secretfinder(self, js_files):
        """Menjalankan SecretFinder pada file .js"""
        print(f"\n{Fore.CYAN}[*] Menjalankan SecretFinder...{Style.RESET_ALL}")
        
        secretfinder_results = []
        
        for js_file in tqdm(js_files, desc="Running SecretFinder"):
            try:
                output_file = self.output_dir / f"secretfinder_{Path(js_file).stem}.html"
                
                # Baca file JS
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Ekstrak secrets menggunakan regex SecretFinder
                secrets = self._extract_secrets_from_js(content)
                
                # Buat HTML report
                html_content = self._create_secretfinder_html_report(js_file, secrets)
                
                # Simpan file HTML
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                secretfinder_results.append({
                    'file': js_file,
                    'output': str(output_file)
                })
                print(f"{Fore.GREEN}[+] SecretFinder selesai untuk {js_file}{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Error menjalankan SecretFinder pada {js_file}: {e}{Style.RESET_ALL}")
        
        return secretfinder_results
    
    def _extract_secrets_from_js(self, content):
        """Ekstrak secrets dari JavaScript content menggunakan regex SecretFinder"""
        import re
        
        # Regex patterns dari SecretFinder
        regex_patterns = {
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
            'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
            'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token': r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"',
            'SSH_privKey': r'([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)',
            'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'possible_Creds': r'(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)'
        }
        
        secrets = []
        
        for secret_type, pattern in regex_patterns.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match and len(str(match)) > 5:  # Filter meaningful secrets
                        secrets.append({
                            'type': secret_type.replace('_', ' ').title(),
                            'value': str(match)[:100] + "..." if len(str(match)) > 100 else str(match)
                        })
            except Exception:
                # Skip invalid regex patterns
                continue
        
        return secrets
    
    def _create_secretfinder_html_report(self, js_file, secrets):
        """Buat HTML report untuk SecretFinder"""
        file_name = Path(js_file).name
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecretFinder Results - {file_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .secret {{ background: #fdf2e9; padding: 8px 12px; margin: 4px 0; border-radius: 4px; border-left: 3px solid #e67e22; }}
        .secret-type {{ font-weight: bold; color: #d35400; }}
        .secret-value {{ font-family: monospace; background: #f8f9fa; padding: 2px 4px; border-radius: 2px; }}
        .no-secrets {{ color: #999; font-style: italic; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SecretFinder Results</h1>
        <p><strong>File:</strong> {file_name}</p>
        <p><strong>Secrets Found:</strong> {len(secrets)}</p>
    </div>
    
    <div style="background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <h2>📋 Discovered Secrets</h2>
"""
        
        if secrets:
            for i, secret in enumerate(secrets, 1):
                html_template += f"""
        <div class="secret">
            <div class="secret-type">{i}. {secret['type']}</div>
            <div class="secret-value">{secret['value']}</div>
        </div>
"""
        else:
            html_template += '        <div class="no-secrets">No secrets found</div>\n'
        
        html_template += """
    </div>
</body>
</html>
"""
        
        return html_template
    
    def generate_report(self, linkfinder_results, secretfinder_results):
        """Membuat laporan akhir"""
        print(f"\n{Fore.CYAN}[*] Membuat laporan akhir...{Style.RESET_ALL}")
        
        report_file = self.output_dir / "final_report.html"
        
        # Buat mapping untuk hasil analisis
        findings_map = {}
        
        # Mapping LinkFinder results
        for result in linkfinder_results:
            file_path = Path(result['file'])
            file_name = file_path.name
            findings_map[file_name] = {
                'url': self._get_original_url(file_name),
                'endpoints': self._extract_endpoints_from_linkfinder(result['output']),
                'secrets': []
            }
        
        # Mapping SecretFinder results
        for result in secretfinder_results:
            file_path = Path(result['file'])
            file_name = file_path.name
            if file_name in findings_map:
                findings_map[file_name]['secrets'] = self._extract_secrets_from_secretfinder(result['output'])
            else:
                findings_map[file_name] = {
                    'url': self._get_original_url(file_name),
                    'endpoints': [],
                    'secrets': self._extract_secrets_from_secretfinder(result['output'])
                }
        
        # Generate table rows
        table_rows = ""
        for file_name, findings in findings_map.items():
            endpoints_html = self._format_list_to_html(findings['endpoints'], 'endpoint')
            secrets_html = self._format_list_to_html(findings['secrets'], 'secret')
            
            # Get js file path for link
            js_file_path = f"js_files/{file_name}"
            
            table_rows += f"""
            <tr>
                <td style="border: 1px solid #ddd; padding: 8px; word-break: break-all;">
                    <strong>{file_name}</strong><br>
                    <small style="color: #666;">{findings['url']}</small><br>
                    <a href="{js_file_path}" style="color: #3498db; font-size: 12px;">📄 View JS File</a>
                </td>
                <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
                    {endpoints_html}
                </td>
                <td style="border: 1px solid #ddd; padding: 8px; vertical-align: top;">
                    {secrets_html}
                </td>
            </tr>
            """
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JS Analyzer Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; flex-wrap: wrap; }}
        .stat-box {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; margin: 10px; min-width: 150px; }}
        .stat-box h2 {{ margin: 0; font-size: 2em; }}
        .stat-box h3 {{ margin: 5px 0; font-size: 1em; opacity: 0.9; }}
        .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .findings-table th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; font-weight: bold; }}
        .findings-table td {{ border: 1px solid #ddd; padding: 12px; vertical-align: top; }}
        .findings-table tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .findings-table tr:hover {{ background-color: #f0f0f0; }}
        .endpoint-item {{ background: #e8f4fd; padding: 4px 8px; margin: 2px 0; border-radius: 4px; border-left: 3px solid #3498db; }}
        .secret-item {{ background: #fdf2e9; padding: 4px 8px; margin: 2px 0; border-radius: 4px; border-left: 3px solid #e67e22; }}
        .no-findings {{ color: #999; font-style: italic; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .risk-high {{ background: #ffebee; border-left: 4px solid #f44336; }}
        .risk-medium {{ background: #fff3e0; border-left: 4px solid #ff9800; }}
        .risk-low {{ background: #e8f5e8; border-left: 4px solid #4caf50; }}
        .quick-links {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .quick-links a {{ color: #3498db; text-decoration: none; margin-right: 15px; }}
        .quick-links a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 JS Analyzer Report</h1>
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>📁 JS Files Found</h3>
            <h2>{len(self.js_files)}</h2>
        </div>
        <div class="stat-box">
            <h3>🔗 LinkFinder Results</h3>
            <h2>{len(linkfinder_results)}</h2>
        </div>
        <div class="stat-box">
            <h3>🔐 SecretFinder Results</h3>
            <h2>{len(secretfinder_results)}</h2>
        </div>
        <div class="stat-box">
            <h3>📊 Total Findings</h3>
            <h2>{len(findings_map)}</h2>
        </div>
    </div>
    
    <div class="section">
        <h2>🔗 Quick Links</h2>
        <div class="quick-links">
            <a href="js_files/">📁 View All JavaScript Files</a>
            <a href="feroxbuster_results.txt">📄 Feroxbuster Results</a>
            <a href="js_files.txt">📋 JS Files List</a>
            <br><br>
            <strong>LinkFinder Reports:</strong><br>
"""
        
        for result in linkfinder_results:
            file_name = Path(result['file']).name
            html_content += f'            <a href="{Path(result["output"]).name}">🔗 {file_name}</a>\n'
        
        html_content += """
            <br><br>
            <strong>SecretFinder Reports:</strong><br>
"""
        
        for result in secretfinder_results:
            file_name = Path(result['file']).name
            html_content += f'            <a href="{Path(result["output"]).name}">🔐 {file_name}</a>\n'
        
        html_content += """
        </div>
    </div>
    
    <div class="section">
        <h2>📋 Discovered JavaScript Files</h2>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
"""
        
        for js_file in self.js_files:
            html_content += f"            <div style='margin: 5px 0;'>• {js_file}</div>\n"
        
        html_content += """
        </div>
    </div>
    
    <div class="section">
        <h2>🔍 Comprehensive Analysis Results</h2>
        <p>Detailed findings combining endpoint discovery and secret detection per JavaScript file:</p>
        
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="width: 25%;">📄 JavaScript File</th>
                    <th style="width: 37.5%;">🔗 Endpoints Found</th>
                    <th style="width: 37.5%;">🔐 Secrets Found</th>
                </tr>
            </thead>
            <tbody>
"""
        
        html_content += table_rows
        
        html_content += """
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>📊 Analysis Summary</h2>
        <div class="summary">
            <h3>🔍 What was analyzed:</h3>
            <ul>
                <li><strong>Feroxbuster:</strong> Web content discovery to find JavaScript files</li>
                <li><strong>LinkFinder:</strong> Endpoint and URL extraction from JavaScript code</li>
                <li><strong>SecretFinder:</strong> Sensitive data and secret detection in JavaScript files</li>
            </ul>
            
            <h3>🎯 Key Findings:</h3>
            <ul>
                <li><strong>Total JS Files:</strong> """ + str(len(self.js_files)) + """ files discovered</li>
                <li><strong>Files with Endpoints:</strong> """ + str(len([f for f in findings_map.values() if f['endpoints']])) + """ files</li>
                <li><strong>Files with Secrets:</strong> """ + str(len([f for f in findings_map.values() if f['secrets']])) + """ files</li>
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h2>🔗 Individual Tool Results</h2>
        <p>For detailed analysis results from each tool:</p>
        
        <h3>LinkFinder Results:</h3>
"""
        
        for result in linkfinder_results:
            html_content += f"""
        <div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">
            <strong>File:</strong> {Path(result['file']).name}<br>
            <a href="{Path(result['output']).name}" style="color: #3498db; text-decoration: none;">📄 View Detailed LinkFinder Results</a>
        </div>
"""
        
        html_content += """
        <h3>SecretFinder Results:</h3>
"""
        
        for result in secretfinder_results:
            html_content += f"""
        <div style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px;">
            <strong>File:</strong> {Path(result['file']).name}<br>
            <a href="{Path(result['output']).name}" style="color: #3498db; text-decoration: none;">📄 View Detailed SecretFinder Results</a>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] Laporan akhir disimpan di: {report_file}{Style.RESET_ALL}")
        return str(report_file)
    
    def _get_original_url(self, file_name):
        """Mendapatkan URL asli dari nama file"""
        # Remove prefix dan suffix dari nama file
        clean_name = file_name.replace('_', '/').replace('.js', '')
        if clean_name.startswith('/'):
            clean_name = clean_name[1:]
        
        # Cari URL yang cocok dari js_files
        for js_url in self.js_files:
            if clean_name in js_url or file_name.replace('_', '/') in js_url:
                return js_url
        
        return f"Unknown URL for {file_name}"
    
    def _extract_endpoints_from_linkfinder(self, output_file):
        """Mengekstrak endpoint dari hasil LinkFinder"""
        endpoints = []
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Parse HTML untuk mendapatkan endpoint dari div class="endpoint"
                soup = BeautifulSoup(content, 'html.parser')
                endpoint_divs = soup.find_all('div', class_='endpoint')
                for div in endpoint_divs:
                    endpoint = div.get_text().strip()
                    if endpoint and len(endpoint) > 3:
                        # Remove numbering (e.g., "1. ", "2. ")
                        if '. ' in endpoint:
                            endpoint = endpoint.split('. ', 1)[1]
                        endpoints.append(endpoint)
        except Exception as e:
            endpoints.append(f"Error parsing: {str(e)}")
        
        return endpoints[:10]  # Limit to 10 endpoints per file
    
    def _extract_secrets_from_secretfinder(self, output_file):
        """Mengekstrak secrets dari hasil SecretFinder"""
        secrets = []
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Parse HTML untuk mendapatkan secrets dari div class="secret"
                soup = BeautifulSoup(content, 'html.parser')
                secret_divs = soup.find_all('div', class_='secret')
                for div in secret_divs:
                    secret_type_div = div.find('div', class_='secret-type')
                    secret_value_div = div.find('div', class_='secret-value')
                    if secret_type_div and secret_value_div:
                        secret_type = secret_type_div.get_text().strip()
                        secret_value = secret_value_div.get_text().strip()
                        # Remove numbering (e.g., "1. ", "2. ")
                        if '. ' in secret_type:
                            secret_type = secret_type.split('. ', 1)[1]
                        secrets.append(f"{secret_type}: {secret_value}")
        except Exception as e:
            secrets.append(f"Error parsing: {str(e)}")
        
        return secrets[:5]  # Limit to 5 secrets per file
    
    def _format_list_to_html(self, items, item_type):
        """Format list items ke HTML"""
        if not items:
            return '<span class="no-findings">No ' + item_type + 's found</span>'
        
        html = ""
        for i, item in enumerate(items, 1):
            css_class = 'endpoint-item' if item_type == 'endpoint' else 'secret-item'
            html += f'<div class="{css_class}">{i}. {item}</div>'
        
        return html
    
    def run_analysis(self, wordlist=None, threads=50, timeout=10):
        """Menjalankan analisis lengkap"""
        self.print_banner()
        
        if not self.check_dependencies():
            return False
        
        # Step 1: Discovery JS files
        if not self.discover_js_files(wordlist, threads, timeout):
            print(f"{Fore.RED}[!] Gagal menemukan file .js{Style.RESET_ALL}")
            return False
        
        # Step 2: Download JS files
        downloaded_files = self.download_js_files()
        if not downloaded_files:
            print(f"{Fore.RED}[!] Tidak ada file .js yang berhasil didownload{Style.RESET_ALL}")
            return False
        
        # Step 3: Run LinkFinder
        linkfinder_results = self.run_linkfinder(downloaded_files)
        
        # Step 4: Run SecretFinder
        secretfinder_results = self.run_secretfinder(downloaded_files)
        
        # Step 5: Generate report
        report_file = self.generate_report(linkfinder_results, secretfinder_results)
        
        print(f"\n{Fore.GREEN}✅ Analisis selesai!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Hasil tersimpan di: {self.output_dir}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Laporan utama: {report_file}{Style.RESET_ALL}")
        
        return True

def main():
    parser = argparse.ArgumentParser(
        description="JS Analyzer Wrapper - Integrates Feroxbuster, LinkFinder, and SecretFinder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python js_analyzer.py -u https://example.com
  python js_analyzer.py -u https://example.com -w /path/to/wordlist.txt
  python js_analyzer.py -u https://example.com -w wordlist.txt -o results -t 100
  python js_analyzer.py -u https://sf7pentest.sunfishhr.com/
  python js_analyzer.py -u https://example.com --no-open-browser
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL untuk dianalisis')
    parser.add_argument('-o', '--output', default='results',
                       help='Direktori output (default: results)')
    parser.add_argument('-w', '--wordlist',
                       help='Wordlist untuk feroxbuster (default: /Users/theninja/SF/SecLists/Discovery/Web-Content/raft-medium-directories.txt)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Jumlah threads untuk feroxbuster (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Timeout untuk feroxbuster (default: 10)')
    parser.add_argument('--no-open-browser', action='store_true',
                       help='Jangan buka browser secara otomatis setelah selesai')
    
    args = parser.parse_args()
    
    analyzer = JSAnalyzer(args.url, args.output)
    success = analyzer.run_analysis(args.wordlist, args.threads, args.timeout)
    
    if success and not args.no_open_browser:
        # Cek apakah user ingin membuka browser
        try:
            import webbrowser
            report_file = analyzer.output_dir / "final_report.html"
            if report_file.exists():
                print(f"\n{Fore.YELLOW}[?] Buka laporan di browser? (y/n): {Style.RESET_ALL}", end="")
                response = input().lower().strip()
                if response in ['y', 'yes', 'ya']:
                    webbrowser.open(f'file://{report_file.absolute()}')
                    print(f"{Fore.GREEN}[+] Browser dibuka{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[*] Laporan tersimpan di: {report_file}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.CYAN}[*] Laporan tersimpan di: {analyzer.output_dir / 'final_report.html'}{Style.RESET_ALL}")
    elif success:
        print(f"{Fore.CYAN}[*] Laporan tersimpan di: {analyzer.output_dir / 'final_report.html'}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Buka manual: open {analyzer.output_dir / 'final_report.html'}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 