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
| `-o OFFSET` | `--offset OFFSET` | Specify partition offset in sectors (avoids interactive input) |
| `-j N` | `--jobs N` | Number of parallel icat extraction jobs (default: 4) |

#### Examples

**Basic usage (fully interactive):**
```bash
./Forensic_Collector_Win.sh
```

**With all parameters:**
```bash
./Forensic_Collector_Win.sh -d "Case_2024_001" -e "/mnt/evidence/disk_image.dd" -o 2048
```

**Partial parameters — offset selected interactively from mmls output:**
```bash
./Forensic_Collector_Win.sh -d "Case_2024_001" -e "/mnt/evidence/disk_image.dd"
```

**With parallel jobs (e.g. 8 threads):**
```bash
./Forensic_Collector_Win.sh -d "Case_2024_001" -e "/mnt/evidence/disk_image.dd" -o 2048 -j 8
```

## 📖 Script Documentation

### Forensic_Collector_Win.sh

**Version:** 2.1

**Description:**
Extracts Windows system artifacts from disk images using SleuthKit (TSK) tools. The script performs comprehensive artifact extraction including registry hives, event logs, prefetch files, scheduled tasks, and more. Supports raw images as well as VMDK, VHD, VHDX, VDI, and qcow2 formats (auto-converted via `qemu-nbd`).

**Extracted Artifacts:**

*Individual files (full path preserved in output):*
- `$MFT` and `$LogFile` (NTFS metadata, by fixed inode)
- Registry hives: `Windows/System32/config/{SYSTEM,SECURITY,SAM,SOFTWARE}`
- User hives: `NTUSER.DAT`, `UsrClass.dat` (all users)
- System files: `pagefile.sys`, `hiberfil.sys`, `Windows/INF/setupapi.dev.log`, `Windows/System32/drivers/etc/hosts`

*Full directory collections:*
- `Windows/Prefetch` — prefetch files (if enabled)
- `Windows/Tasks` — legacy scheduled tasks
- `Windows/System32/Tasks` — scheduled tasks (XML format)
- `Windows/System32/config/RegBack` — registry hive backups
- `Windows/System32/sru` — SRUM database (if present)
- `Windows/System32/winevt/Logs` — all Windows event logs (`.evtx`)
- `Windows/System32/Logfiles/W3SVC1` — IIS logs (if present)
- `Windows/appcompat/Programs` — Amcache / AppCompat
- `$Recycle.Bin` — recycle bin metadata

*Deleted file recovery:*
- Unallocated space carving via `tsk_recover` (deleted/carved files only)

**Features:**
- ✅ Automatic requirement checking
- ✅ Interactive partition selection from `mmls` output (or `-o` to skip)
- ✅ Parallel extraction with configurable job count (`-j`)
- ✅ `tsk_recover` runs concurrently with `icat` extractions
- ✅ Auto-conversion of non-raw images (VMDK, VHD, qcow2…)
- ✅ BitLocker encryption detection
- ✅ MD5 hash calculation for all extracted files
- ✅ Full directory structure preserved in output
- ✅ Comprehensive timestamped logging
- ✅ Command-line and interactive modes

**Output Structure:**
```
CaseDirectory/
├── result_icat/
│   ├── MFT
│   ├── LogFile
│   ├── Windows/
│   │   ├── System32/config/{SYSTEM,SECURITY,SAM,SOFTWARE}
│   │   ├── System32/winevt/Logs/*.evtx
│   │   ├── System32/sru/
│   │   ├── System32/Tasks/
│   │   ├── Prefetch/
│   │   └── appcompat/Programs/
│   ├── Users/<username>/NTUSER.DAT
│   ├── fls_full.txt
│   └── md5sum.txt
├── result_tsk_recover/
│   └── (deleted/carved files from unallocated space)
├── md5sum.txt
├── tsk_recover.log
└── forensic_collector.log
```

**Workflow:**
1. Checks for required tools (`mmls`, `icat`, `fls`, `tsk_recover`, `xxd`, `dd`, `md5sum`)
2. Creates case directory structure
3. Validates evidence file and calculates MD5 hash
4. Auto-converts non-raw images if needed
5. Displays `mmls` partition layout — user selects the Windows partition interactively (or `-o` bypasses this)
6. Checks for BitLocker encryption
7. Extracts `$MFT` and `$LogFile` by fixed NTFS inode
8. Builds full filesystem listing once with `fls -r -p` (full paths)
9. Extracts individual targeted files in parallel (`-j` jobs)
10. Extracts full directory collections in parallel
11. Runs `tsk_recover` (unallocated/deleted files) concurrently in the background
12. Generates summary report with MD5 count

**Error Handling:**
- Validates all inputs and checks file existence/permissions
- Detects encrypted volumes (BitLocker)
- Verifies available disk space before image conversion
- Handles extraction failures gracefully with per-file warnings
- Provides detailed timestamped error messages in log

## 📁 Project Structure

```
Forensic-Scripts/
├── README.md                    # This file
├── Forensic_Collector_Win.sh    # Windows artifact extraction script
└── [Future scripts...]          # Additional forensic scripts
```

