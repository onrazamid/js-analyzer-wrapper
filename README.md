# JS Analyzer Wrapper

A powerful Python wrapper that integrates **Feroxbuster**, **LinkFinder**, and **SecretFinder** to automatically discover and analyze JavaScript files from web applications.

## 🚀 Features

- **🔍 JS Discovery**: Uses Feroxbuster to discover JavaScript files from target websites
- **🔗 Endpoint Extraction**: Integrated LinkFinder functionality to extract endpoints from JS files
- **🔐 Secret Detection**: Integrated SecretFinder functionality to detect secrets in JS files
- **📊 HTML Reporting**: Generates comprehensive HTML reports with clickable links
- **🎯 Smart Output**: Auto-generates output folders based on target URL
- **⚡ CLI Interface**: Easy-to-use command line interface

## 📋 Requirements

### System Dependencies
- **Feroxbuster**: Web content discovery tool
- **Python 3.7+**: Python runtime

### Python Dependencies
```
requests
beautifulsoup4
colorama
tqdm
urllib3
```

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd jsthings
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Install Feroxbuster:**
```bash
# macOS
brew install feroxbuster

# Linux
curl -s https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
```

## 🎯 Usage

### Basic Usage
```bash
python3 js_analyzer.py -u https://example.com
```

### Advanced Usage
```bash
python3 js_analyzer.py \
  -u https://example.com \
  -w /path/to/wordlist.txt \
  --threads 50 \
  --timeout 300 \
  --no-open-browser
```

### Command Line Options
- `-u, --url`: Target URL (required)
- `-o, --output`: Output directory (default: auto-generated)
- `-w, --wordlist`: Wordlist for Feroxbuster (default: SecLists raft-medium)
- `--threads`: Number of threads (default: 50)
- `--timeout`: Timeout in seconds (default: 300)
- `--no-open-browser`: Don't open browser automatically

## 📁 Output Structure

The tool creates an organized output structure:

```
output/
└── https_example.com/
    ├── js_files/                    # Downloaded JS files
    ├── linkfinder_reports/          # LinkFinder HTML reports
    ├── secretfinder_reports/        # SecretFinder HTML reports
    ├── feroxbuster_results.txt      # Raw Feroxbuster results
    ├── js_files.txt                 # List of discovered JS files
    └── final_report.html           # Comprehensive summary report
```

## 📊 Report Features

### Final HTML Report
- **Summary Statistics**: Total files, endpoints, and secrets found
- **Interactive Table**: Clickable links to individual reports
- **File Downloads**: Direct links to downloaded JS files
- **Endpoint Analysis**: Links to LinkFinder reports per file
- **Secret Analysis**: Links to SecretFinder reports per file

### Individual Reports
- **LinkFinder Reports**: Endpoint extraction results per JS file
- **SecretFinder Reports**: Secret detection results per JS file
- **Clickable Links**: Direct navigation to discovered resources

## 🔧 Configuration

### Default Wordlist
The tool uses SecLists by default:
```
/Users/theninja/SF/SecLists/Discovery/Web-Content/raft-medium-directories.txt
```

### Custom Wordlists
You can specify custom wordlists:
```bash
python3 js_analyzer.py -u https://example.com -w /path/to/custom/wordlist.txt
```

## 🐛 Troubleshooting

### Common Issues

1. **Feroxbuster not found:**
   ```bash
   # Install Feroxbuster
   brew install feroxbuster
   ```

2. **Timeout issues:**
   ```bash
   # Increase timeout
   python3 js_analyzer.py -u https://example.com --timeout 600
   ```

3. **Permission errors:**
   ```bash
   # Check permissions
   chmod +x js_analyzer.py
   ```

## 📈 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    JS Analyzer Wrapper v1.0                        ║
║  Integrates: Feroxbuster + LinkFinder + SecretFinder              ║
╚══════════════════════════════════════════════════════════════════════╝

[*] Memeriksa dependencies...
[+] Feroxbuster ditemukan: /opt/homebrew/bin/feroxbuster
[+] LinkFinder: Integrated dalam script
[+] SecretFinder: Integrated dalam script

[*] Memulai discovery file .js menggunakan Feroxbuster...
[+] Found JS: https://example.com/app.js
[+] Found JS: https://example.com/api/config.js
[+] Found JS: https://example.com/static/main.js

[*] Downloading JS files...
[+] Downloaded: app.js (2.1 KB)
[+] Downloaded: config.js (1.8 KB)
[+] Downloaded: main.js (3.2 KB)

[*] Running LinkFinder analysis...
[+] LinkFinder completed for app.js (5 endpoints found)
[+] LinkFinder completed for config.js (3 endpoints found)
[+] LinkFinder completed for main.js (8 endpoints found)

[*] Running SecretFinder analysis...
[+] SecretFinder completed for app.js (2 secrets found)
[+] SecretFinder completed for config.js (1 secret found)
[+] SecretFinder completed for main.js (0 secrets found)

[*] Generating final report...
[+] Final report saved: output/https_example.com/final_report.html
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Feroxbuster**: Web content discovery tool
- **LinkFinder**: JavaScript endpoint extraction tool
- **SecretFinder**: JavaScript secret detection tool
- **SecLists**: Security testing wordlists

## 📞 Support

For issues and questions, please open an issue on GitHub. 