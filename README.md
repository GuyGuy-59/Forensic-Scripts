# Forensic Scripts

A collection of forensic analysis scripts for digital investigations. This repository contains various tools and utilities designed to assist in digital forensics, incident response, and security analysis.

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Script Documentation](#script-documentation)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This repository provides a comprehensive set of forensic scripts for analyzing digital evidence. The scripts are designed to work with various forensic tools and formats, supporting both Windows and Linux environments.

## 📜 Scripts

### Available Scripts

| Script | Description | Platform |
|--------|-------------|----------|
| `Forensic_Collector_Win.sh` | Extracts Windows system artifacts from disk images | Linux/WSL |

## 🔧 Requirements

### General Requirements

- **Bash** (version 4.0 or higher)
- **SleuthKit (TSK)** - Required for disk image analysis
- **Core utilities**: `dd`, `xxd`, `md5sum`, `grep`, `awk`, `cut`

### Installing SleuthKit

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install sleuthkit
```

#### CentOS/RHEL
```bash
sudo yum install sleuthkit
```

#### macOS
```bash
brew install sleuthkit
```

#### Windows (WSL)
```bash
sudo apt-get update
sudo apt-get install sleuthkit
```

## 📦 Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/Forensic-Scripts.git
cd Forensic-Scripts
```

2. Make scripts executable:
```bash
chmod +x *.sh
```

3. Verify SleuthKit installation:
```bash
mmls -V
icat -V
fls -V
```

## 🚀 Usage

### Forensic Collector for Windows

The `Forensic_Collector_Win.sh` script extracts Windows forensic artifacts from disk images using SleuthKit tools.

#### Interactive Mode

Run the script without arguments for interactive prompts:

```bash
./Forensic_Collector_Win.sh
```

#### Command Line Mode

Use command-line arguments to avoid interactive prompts:

```bash
./Forensic_Collector_Win.sh -d "Case001" -e "/path/to/image.dd" -o 2048
```

#### Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-h` | `--help` | Display help message |
| `-v` | `--version` | Display script version |
| `-d DIR` | `--directory DIR` | Specify case directory (avoids interactive input) |
| `-e FILE` | `--evidence FILE` | Specify evidence file path (avoids interactive input) |
| `-o OFFSET` | `--offset OFFSET` | Specify partition offset (avoids interactive input) |

#### Examples

**Basic usage:**
```bash
./Forensic_Collector_Win.sh
```

**With all parameters:**
```bash
./Forensic_Collector_Win.sh -d "Case_2024_001" -e "/mnt/evidence/disk_image.dd" -o 2048
```

**Partial parameters (will prompt for missing ones):**
```bash
./Forensic_Collector_Win.sh -d "Case_2024_001" -e "/mnt/evidence/disk_image.dd"
```

## 📖 Script Documentation

### Forensic_Collector_Win.sh

**Version:** 2.0

**Description:**
Extracts Windows system artifacts from disk images using SleuthKit (TSK) tools. The script performs comprehensive artifact extraction including registry files, event logs, and system files.

**Extracted Artifacts:**
- Master File Table (MFT)
- Registry hives: SYSTEM, SECURITY, SAM, SOFTWARE
- User profiles: NTUSER.DAT
- Event logs: Setup.evtx, System.evtx, Security.evtx, Parameters.evtx, Application.evtx
- System files: pagefile.sys
- Complete file system recovery using tsk_recover

**Features:**
- ✅ Automatic requirement checking
- ✅ Encryption detection (BitLocker)
- ✅ MD5 hash calculation for all extracted files
- ✅ Comprehensive logging with timestamps
- ✅ Error handling and validation
- ✅ Command-line and interactive modes
- ✅ Progress tracking and summary reports

**Output Structure:**
```
CaseDirectory/
├── result_icat/
│   ├── MFT
│   ├── SYSTEM
│   ├── SECURITY
│   ├── SAM
│   ├── SOFTWARE
│   ├── NTUSER.DAT
│   ├── *.evtx files
│   ├── pagefile.sys
│   ├── fls_output.txt
│   └── md5sum.txt
├── result_tsk_recover/
│   └── (recovered file system)
├── md5sum.txt
└── forensic_collector.log
```

**Workflow:**
1. Checks for required tools (mmls, icat, fls, tsk_recover, etc.)
2. Creates case directory structure
3. Validates evidence file and calculates MD5 hash
4. Displays partition layout
5. Checks for encryption (BitLocker)
6. Extracts MFT (Master File Table)
7. Searches and extracts registry hives and system files
8. Performs full file system recovery
9. Generates MD5 hashes for all extracted files
10. Creates summary report

**Error Handling:**
- Validates all inputs
- Checks file existence and permissions
- Detects encrypted volumes
- Handles extraction failures gracefully
- Provides detailed error messages

## 📁 Project Structure

```
Forensic-Scripts/
├── README.md                    # This file
├── Forensic_Collector_Win.sh    # Windows artifact extraction script
└── [Future scripts...]          # Additional forensic scripts
```

