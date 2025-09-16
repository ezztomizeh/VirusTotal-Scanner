# 🛡️ VirusTotal Scanner (Python CLI)

A command-line interface (CLI) tool that integrates with the [VirusTotal API v3](https://developers.virustotal.com/reference) to scan URLs, files, and domains, as well as calculate file hashes.
The tool provides **colored output**, **ASCII banners**, and formatted **WHOIS summaries** using `rich`.

---

## ✨ Features

* 🔗 **Scan URLs** — check if a website is malicious/suspicious.
* 📄 **Scan Files** — upload files to VirusTotal (with optional password for protected archives).
* 🌐 **Scan Domains** — fetch last analysis stats + WHOIS summary in a styled panel.
* 🔑 **Calculate File Hashes** — SHA-256 hashing for integrity checks.
* 🎨 **Colorful CLI Output** — using `colorama` + `rich` for a clean experience.
* 🖼️ **ASCII Banner** — powered by `pyfiglet`.

---

## 📦 Requirements

Install the required dependencies:

```bash
pip install requests colorama pyfiglet rich
```

---

## 🔑 Setup API Key

You need a **VirusTotal API key** (free tier works, but limited to 4 requests/minute).

1. Get your key from [VirusTotal](https://www.virustotal.com/gui/my-apikey).
2. Set it as an environment variable:

### Linux / macOS

```bash
export VIRUSTOTAL_KEY="your_api_key_here"
```

### Windows (PowerShell)

```powershell
setx VIRUSTOTAL_KEY "your_api_key_here"
```

---

## ▶️ Usage

Run the program:

```bash
python main.py
```

You’ll see:

```
 __      ___                  _____         _       _ 
 \ \    / (_)                |_   _|       | |     | |
  \ \  / / _  _____      __    | | ___  ___| |_ ___| |
   \ \/ / | |/ _ \ \ /\ / /    | |/ _ \/ __| __/ _ \ |
    \  /  | |  __/\ V  V /     | |  __/\__ \ ||  __/ |
     \/   |_|\___| \_/\_/      \_/\___||___/\__\___|_|

Made by : Eng. Ezzudin Tomizi
--------------------------------------------------

     1) Scan URL
     2) File Hash Calculate
     3) Scan A File
     4) Scan A Domain
     5) Help
     6) Exit
```

---

## 🛠 Example Workflows

### 1. Scan a URL

```
:\> Enter URL: https://example.com
malicious: 0
suspicious: 0
harmless: 89
undetected: 5
```

### 2. Calculate File Hash

```
:\> Enter File Path: sample.exe
The hash value is: 5d41402abc4b2a76b9719d911017c592
```

### 3. Scan a File

```
:\> Enter File Path: document.pdf
:\> Enter File Password -if exists- : 
malicious: 2
suspicious: 1
harmless: 65
undetected: 10
```

### 4. Scan a Domain

```
:\> Enter The Domain: example.com
malicious: 0
suspicious: 0
harmless: 90
undetected: 3
```

And the WHOIS summary is displayed inside a **rich panel**:

```
┌────────────── WHOIS Summary ──────────────┐
│ Domain Name: example.com                  │
│ Registrar: Example Registrar Inc.         │
│ Creation Date: 1995-08-14                 │
│ Expiry Date:   2030-08-14                 │
└───────────────────────────────────────────┘
```

---

## ⚠️ Notes

* Free VirusTotal API keys are **rate-limited** (4 requests/minute).
* `sha256` is used for hashing by default (stronger than MD5/SHA1).
* Requires **internet access** to function.

---

## 👨‍💻 Author

Made by **Eng. Ezzudin Tomizi**
