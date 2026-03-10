<div align="center">
  <h1>🛡️ Automated Static Malware Analyzer</h1>
  <p>A scalable, hybrid (Local & AWS Cloud) platform for deep static analysis of potentially malicious files.</p>
</div>

## 📖 Overview
This project provides a comprehensive static malware analysis pipeline. It extracts metadata, detects packing, analyzes Windows PE structures, scans with YARA/ClamAV, and calculates fuzzy hashes (ssdeep). It supports both **Standalone Local Execution** and an **Automated AWS Air-Gapped Cloud Execution** via Terraform.

---

## ⚠️ CRITICAL SETUP INSTRUCTIONS (Must Read)

If you are cloning this project to use on your own AWS infrastructure or locally, you must perform the following setup steps to avoid dependency and infrastructure errors.

### 1. Preparing the AWS Environment (Custom AMI Creation)
To ensure the automated analyzing instances boot quickly and run reliably without dependency resolution errors, **you must create a custom Linux AMI**.

1. **Launch a Base EC2 Instance**: Create a clean Ubuntu/Debian Linux instance in your AWS account.
2. **Transfer Setup Script**: Copy the `setup.sh` file to this new instance.
3. **Run the Script**: Execute the script to install all necessary dependencies (YARA, ssdeep, ClamAV, radare2, pefile, python-magic, etc.).
   ```bash
   chmod +x setup.sh
   sudo ./setup.sh
   ```
4. **Create the AMI**: Once the script completes successfully and all tools are installed, go to your AWS Console, right-click the running EC2 instance, and select **Image and templates > Create image**. 
5. **Update Configuration**: Copy the generated **AMI ID** (e.g., `ami-0abcdef1234567890`) from your AWS dashboard.

### 2. Configuration (`config.json`)
Rename `config.json.example` to `config.json` and replace the placeholder fields with your actual AWS values:
- `linux_ami_id`: **Paste the AMI ID you just created in Step 1.**
- `vpc_cidr` & `subnet_cidrs`: Update if you have specific network requirements.
- `region`: Ensure the AMI you built resides in the correct AWS region specified here.

### 3. API Keys (`.env`)
Rename `.env.example` to `.env`.
To use external lookup modules, provide your API keys:
```env
VT_API_KEY=your_virustotal_api_key_here
```
*(If you do not provide keys, the analyzer will gracefully skip the external lookup tests and perform offline heuristic analysis).*

### 4. IAM / AWS Credentials (Cloud Only)
If you plan to use the AWS automated method, you must have the AWS CLI installed and configured with appropriate IAM user credentials (with EC2, VPC, S3 permissions) on your host machine.
```bash
aws configure
```

---

## 🚀 Usage Guide

### Method A: AWS Cloud Orchestration (Air-Gapped)
Use this method to automatically spin up a secure, isolated EC2 instance, analyze the malware, retrieve the results, and tear down the infrastructure.

1. **Deploy Infrastructure**:
   ```bash
   terraform init
   terraform apply -auto-approve
   ```
2. **Run the Orchestrator**:
   ```bash
   python3 malware_analysis_orchestrator.py /path/to/malware/sample.exe
   ```
3. **View Results**: The orchestrator will download a JSON report and a human-readable `report.txt` parsed by `parser.py` into your working directory.

### Method B: Local Standalone Execution
If you wish to run the analysis engine directly on your own Linux machine without touching AWS.

1. First, ensure you have run `setup.sh` on your local environment to resolve all Python and system dependencies!
   ```bash
   sudo ./setup.sh
   ```
2. Run the local analyzer:
   ```bash
   python3 local_static_analyzer.py /path/to/malware/sample.exe
   ```
   *Note: This will automatically generate both a `results.json` and a human-readable `results.txt` report.*

---

## 🛠️ Architecture
- **`main.tf`**: Provisions the secure VPC, private subnets, security groups, IAM roles, and VPC Endpoints for S3 entirely for static analysis.
- **`malware_analysis_orchestrator.py`**: The "Master" script. Uploads samples to S3, dispatches the EC2 instances, polls for completion, and cleans up.
- **`malware_static_analyzer.py`**: The core "Agent" payload that runs headlessly inside the isolated cloud EC2 instance.
- **`local_static_analyzer.py`**: The full-featured standalone static analyzer for local/offline analysis without AWS requirements.
- **`parser.py`**: Translates the dense JSON output into an analyst-friendly text report highlighting risk scores and matched rules.
