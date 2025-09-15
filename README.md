# README.md

# 🕵️ Stego Terminal Tool 

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Security](https://img.shields.io/badge/security-cybersecurity-red) ![Version](https://img.shields.io/badge/version-1.0-blueviolet)

**A lightweight command-line steganography tool** to hide and retrieve messages or files in images (PNG/BMP) using **Least Significant Bit (LSB)**. Optional **AES encryption** via `cryptography`.

---

## ⚠ Important Warnings

* Only use this tool on **your own images**.
* AES encryption is optional but recommended for sensitive data.
* Always check payload to **avoid overwriting images**.
* Use responsibly and ethically.

---

##  Virtual Environment

It is recommended to use a **Python virtual environment** to manage dependencies safely.

### Create and activate a virtual environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Linux / MacOS
source venv/bin/activate
```

### Install dependencies inside the virtual environment

```bash
pip install -r requirements.txt
```

>  Always activate the virtual environment before running the script.

---

##  Installation

### Step 1: Clone the repo
```bash
git clone https://github.com/your-username/stego-terminal-tool.git
cd stego-terminal-tool
```

### Step 2: Run the program
```bash
python3 stego-terminal-tool.py
```

---

##  Menu Options

| Option | Action |
|--------|--------|
| e | Encode (hide message/file) |
| d | Decode (extract hidden data) |
| i | Info (check image capacity & payload) |
| q | Quit |

---

##  Example Workflow

```bash
# 1. Create cover image
python3 - <<'PY'
from PIL import Image
img = Image.new('RGB', (200,200), (255,255,255))
img.save('cover.png')
PY

# 2. Encode message
python3 stego-terminal-tool.py encode --in cover.png --out secret.png --message "Hello Cyber"

# 3. Check payload
python3 stego-terminal-tool.py info --in secret.png

# 4. Decode message
python3 stego-terminal-tool.py decode --in secret.png
```
---

##  Features

| Feature | Description |
|---------|------------|
|  AES Encryption | Optional password-protect your payload |
|  File & Text | Embed messages or binary files |
|  Payload Detection | Check image for hidden content |
|  Single-file CLI | Run the script directly |

---

##  Requirements

| Package | Version |
|---------|---------|
| Pillow | Latest |
| cryptography | Latest (optional) |

Install with:
```bash
pip install -r requirements.txt
```

---

##  License

This project is licensed under the **MIT License** — see `LICENSE`.

---

##  Contribute

1. Fork the repo  
2. Create a branch: `git checkout -b feature/my-feature`  
3. Commit & push, then open a Pull Request  

---

Made with for Cybersecurity & Ethical Hacking
