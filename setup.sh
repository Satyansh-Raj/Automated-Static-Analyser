#!/bin/bash
# =============================================================================
# Malware Analysis Environment Setup Script
# Run: chmod +x setup.sh && sudo ./setup.sh
# =============================================================================

set -e

echo "========================================="
echo "Malware Analysis Environment Setup"
echo "(Static Analysis)"
echo "========================================="

# Detect if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[INFO] Running as root"
    SUDO=""
else
    echo "[INFO] Running as user (using sudo where needed)"
    SUDO="sudo"
fi

# Always use --break-system-packages for modern Kali/Debian with Python 3.11+
PIP_FLAGS="--break-system-packages"

# =============================================================================
# STEP 1: SYSTEM PACKAGES
# =============================================================================
echo ""
echo "[1/6] Installing system packages..."
$SUDO apt-get update -y
$SUDO apt-get install -y \
    python3 python3-pip python3-dev python3-venv build-essential \
    libssl-dev libffi-dev libmagic-dev libfuzzy-dev \
    ssdeep yara clamav clamav-daemon \
    git wget curl unzip p7zip-full upx-ucl \
    libimage-exiftool-perl \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-xlib-2.0-0 \
    libcairo2 libgirepository1.0-dev

# =============================================================================
# STEP 2: PYTHON PACKAGES (All-in-one, no requirements.txt needed)
# =============================================================================
echo ""
echo "[2/6] Installing Python packages..."
pip3 install --upgrade pip $PIP_FLAGS

# --- AWS Integration ---
pip3 install $PIP_FLAGS \
    boto3 \
    botocore

# --- SSH and Remote Execution ---
pip3 install $PIP_FLAGS \
    paramiko \
    pywinrm

# --- Malware Analysis Libraries ---
pip3 install $PIP_FLAGS \
    python-magic \
    pefile \
    ssdeep \
    yara-python \
    capstone \
    pyelftools

# --- Office Document Analysis ---
pip3 install $PIP_FLAGS \
    oletools

# --- Cryptography ---
pip3 install $PIP_FLAGS \
    pycryptodome

# --- Web/HTTP ---
pip3 install $PIP_FLAGS \
    requests \
    beautifulsoup4 \
    lxml

# --- Image Processing ---
pip3 install $PIP_FLAGS \
    pillow

# --- Report Generation ---
pip3 install $PIP_FLAGS \
    reportlab \
    jinja2 \
    markdown \
    weasyprint

# --- Data Processing ---
pip3 install $PIP_FLAGS \
    pandas \
    numpy

# --- Utilities ---
pip3 install $PIP_FLAGS \
    python-dateutil \
    pytz \
    colorama \
    tqdm

# --- Monitoring/Logging ---
pip3 install $PIP_FLAGS \
    python-json-logger

# --- Development Tools (optional, for testing) ---
pip3 install $PIP_FLAGS \
    pytest \
    black \
    flake8 \
    mypy

# =============================================================================
# STEP 3: YARA RULES
# =============================================================================
echo ""
echo "[3/6] Downloading YARA rules..."
$SUDO mkdir -p /opt/yara-rules
if [ ! -d "/opt/yara-rules/rules" ]; then
    $SUDO git clone --depth 1 https://github.com/Yara-Rules/rules.git /opt/yara-rules/rules
else
    echo "[OK] YARA rules already exist"
fi
if [ ! -d "/opt/yara-rules/signature-base" ]; then
    $SUDO git clone --depth 1 https://github.com/Neo23x0/signature-base.git /opt/yara-rules/signature-base
else
    echo "[OK] Signature-base already exists"
fi

# =============================================================================
# STEP 4: CLAMAV UPDATE
# =============================================================================
echo ""
echo "[4/6] Updating ClamAV database..."
$SUDO systemctl stop clamav-freshclam 2>/dev/null || true
$SUDO freshclam 2>/dev/null || echo "[WARN] ClamAV update failed (non-critical)"
$SUDO systemctl start clamav-freshclam 2>/dev/null || true

# =============================================================================
# STEP 5: AWS CLI (optional, for AWS mode)
# =============================================================================
echo ""
echo "[5/6] Checking AWS CLI..."
if ! command -v aws &> /dev/null; then
    echo "[+] Installing AWS CLI..."
    curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    $SUDO ./aws/install
    rm -rf awscliv2.zip aws/
else
    echo "[OK] AWS CLI already installed"
fi

# =============================================================================
# STEP 6: WORKING DIRECTORIES & VERIFICATION
# =============================================================================
echo ""
echo "[6/6] Creating directories and verifying..."
mkdir -p ~/malware-analysis/{samples,reports,tools,temp}

# Verify key packages
echo ""
echo "Verifying installations..."
python3 -c "import winrm; print('[OK] pywinrm')" 2>/dev/null || echo "[FAIL] pywinrm"
python3 -c "import paramiko; print('[OK] paramiko')" 2>/dev/null || echo "[FAIL] paramiko"
python3 -c "import boto3; print('[OK] boto3')" 2>/dev/null || echo "[FAIL] boto3"
python3 -c "import pefile; print('[OK] pefile')" 2>/dev/null || echo "[FAIL] pefile"
python3 -c "import yara; print('[OK] yara-python')" 2>/dev/null || echo "[FAIL] yara-python"
python3 -c "import magic; print('[OK] python-magic')" 2>/dev/null || echo "[FAIL] python-magic"
python3 -c "import ssdeep; print('[OK] ssdeep')" 2>/dev/null || echo "[FAIL] ssdeep"
python3 -c "import capstone; print('[OK] capstone')" 2>/dev/null || echo "[FAIL] capstone"
python3 -c "import oletools; print('[OK] oletools')" 2>/dev/null || echo "[FAIL] oletools"
python3 -c "import pandas; print('[OK] pandas')" 2>/dev/null || echo "[FAIL] pandas"

# =============================================================================
# COMPLETE
# =============================================================================
echo ""
echo "========================================="
echo "           Setup Complete!"
echo "========================================="