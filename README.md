# 🔐 StegoVault

**Professional Steganography Tool for Secure Message Hiding**

StegoVault is a comprehensive steganography application that allows you to hide secret messages inside images using LSB (Least Significant Bit) steganography with optional AES encryption. Available in both GUI and CLI modes, it provides flexible interfaces for secure communication.

## ✨ Features

### 🔒 **Steganography**
- **LSB (Least Significant Bit)** embedding algorithm
- Support for **PNG** and **BMP** image formats only
- Real-time **capacity calculation** showing maximum message size
- Character count validation with visual feedback
- Invisible data embedding with no visual artifacts

### 🛡️ **Security & Encryption**
- **AES-256 encryption** using Fernet (symmetric encryption)
- **PBKDF2-HMAC-SHA256** key derivation with 100,000 iterations
- **16-byte cryptographically secure** random salt per message
- **Password strength validation** with real-time feedback
- **Secure password generator** (12+ characters with mixed character types)

### 🎨 **Dual Interface Options**
- **GUI Mode (Default)**
- **CLI Mode**

## 🚀 Quick Start

### Prerequisites
- **Python 3.6+** installed on your system
- **pip** package manager

### Installation

1. **Clone or download** the project files
2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

### Launch Application

#### **GUI Mode (Default)**
```bash
python app.py
# or
python app.py gui
```

#### **CLI Mode**
```bash
python app.py cli [command] [options]
```

### Manual Installation
```bash
pip install Pillow>=9.0.0 cryptography>=3.4.8
# tkinter is built-in with most Python installations
```

## 📋 CLI Usage Guide

### **Hide Messages**
```bash
# Hide text message
python app.py cli hide image.png "Secret message"

# Hide message from file
python app.py cli hide image.png message.txt

# Hide with password protection
python app.py cli hide image.png "Secret" -p "mypassword"

# Hide with secure password prompt
python app.py cli hide image.png "Secret" -p prompt

# Specify output file
python app.py cli hide image.png "Secret" -o output.png
```

### **Extract Messages**
```bash
# Extract plain message
python app.py cli extract secret.png

# Extract encrypted message with password
python app.py cli extract secret.png -p "mypassword"

# Extract with secure password prompt
python app.py cli extract secret.png -p prompt

# Save extracted message to file
python app.py cli extract secret.png -o message.txt
```

### **Image Analysis**
```bash
# Show image capacity and details
python app.py cli info image.png
```

### **Password Generation**
```bash
# Generate 12-character password (default)
python app.py cli generate-password

# Generate custom length password
python app.py cli generate-password 16
```

### **CLI Command Reference**

| Command | Description | Options |
|---------|-------------|---------|
| `hide` | Hide message in image | `-p` password, `-o` output file |
| `extract` | Extract hidden message | `-p` password, `-o` output file |
| `info` | Show image information | None |
| `generate-password` | Generate secure password | `[length]` (default: 12) |

#### **CLI Options**
- `-p, --password` - Password for encryption/decryption (use "prompt" for secure input)
- `-o, --output` - Output file path
- `-h, --help` - Show help message

## 🛠️ Technical Specifications

### Supported Image Formats
| Format | Hide Support | Extract Support | Notes |
|--------|--------------|-----------------|-------|
| PNG    | ✅ Yes       | ✅ Yes          | **Recommended** - Lossless compression |
| BMP    | ✅ Yes       | ✅ Yes          | **Recommended** - No compression |
| JPEG   | ❌ No        | ❌ No           | Lossy compression destroys hidden data |

### Capacity Calculation
The hiding capacity depends on image dimensions and color channels:
- **RGB Images**: 3 bits per pixel available for data
- **RGBA Images**: 4 bits per pixel available for data
- **Grayscale**: Converted to RGB (3 bits per pixel)

**Formula**: `Capacity = (Width × Height × Channels ÷ 8) - 6 bytes`
*(6 bytes reserved for 32-bit length header + 16-bit terminator)*

### Data Structure
Each hidden message uses this format:
1. **32-bit length header** - Specifies message length in bytes
2. **Message data** - Actual message or encrypted data
3. **16-bit terminator** - Pattern: `1111111111111110`

## 🔧 Project Structure

```
stegovault/
├── app.py                 # Main application entry point & dependency checking
├── requirements.txt       # Python dependencies
└── src/
    ├── __init__.py        # Python package marker
    ├── gui.py             # Tkinter GUI interface
    ├── cli.py             # Command-line interface
    ├── steganography.py   # LSB embedding/extraction algorithms
    └── crypto_utils.py    # AES encryption & password utilities
```

## ⚠️ Legal Disclaimer

This software is intended for educational and legitimate privacy purposes only. Users are responsible for ensuring compliance with local laws and regulations. The developers are not responsible for any misuse of this software.

## 🤝 Contributing

Contributions are welcome! Please ensure any new features maintain the security standards and user experience of the existing application.
