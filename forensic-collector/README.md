# Forensic Collector for Windows

Extracts Windows forensic artifacts from disk images using [SleuthKit](https://www.sleuthkit.org/) (TSK). Supports raw images and virtual disk formats (VMDK, VHD, VHDX, VDI, qcow2 — auto-converted via `qemu-nbd`).

---

## Requirements

| Tool | Purpose |
|------|---------|
| `mmls`, `icat`, `fls`, `tsk_recover` | SleuthKit — disk image parsing and extraction |
| `dd`, `xxd`, `md5sum` | Core utilities |
| `qemu-nbd` *(optional)* | Non-raw image conversion |

```bash
# Debian / Ubuntu / WSL
sudo apt-get install sleuthkit

# CentOS / RHEL
sudo yum install sleuthkit

# macOS
brew install sleuthkit
```

---

## Usage

```bash
chmod +x Forensic_Collector_Win.sh

# Interactive — prompts for all inputs
./Forensic_Collector_Win.sh

# Non-interactive
./Forensic_Collector_Win.sh -d "Case001" -e "/path/to/image.dd" -o 2048

# 8 parallel extraction threads
./Forensic_Collector_Win.sh -d "Case001" -e "/path/to/image.dd" -o 2048 -j 8
```

### Options

| Option | Long form | Description |
|--------|-----------|-------------|
| `-h` | `--help` | Display help |
| `-v` | `--version` | Display version |
| `-d DIR` | `--directory DIR` | Case directory name |
| `-e FILE` | `--evidence FILE` | Path to the evidence image |
| `-o OFFSET` | `--offset OFFSET` | Windows partition offset in sectors |
| `-j N` | `--jobs N` | Parallel `icat` jobs (default: 4) |

When `-o` is omitted, `mmls` output is displayed and the offset is selected interactively.

---

## Extracted Artifacts

**Individual files** (directory structure preserved):

| Artifact | Location in image |
|----------|-------------------|
| `$MFT`, `$LogFile` | NTFS metadata (fixed inode) |
| Registry hives | `Windows/System32/config/{SYSTEM,SECURITY,SAM,SOFTWARE}` |
| Registry backups | `Windows/System32/config/RegBack/` |
| User hives | `Users/*/NTUSER.DAT`, `Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat` |
| Page / hibernate | `pagefile.sys`, `hiberfil.sys` |
| Setup log | `Windows/INF/setupapi.dev.log` |
| Hosts file | `Windows/System32/drivers/etc/hosts` |

**Full directory collections:**

| Directory | Contents |
|-----------|----------|
| `Windows/Prefetch/` | Prefetch files |
| `Windows/Tasks/` + `Windows/System32/Tasks/` | Scheduled tasks |
| `Windows/System32/sru/` | SRUM database |
| `Windows/System32/winevt/Logs/` | All `.evtx` event logs |
| `Windows/System32/Logfiles/W3SVC1/` | IIS logs |
| `Windows/appcompat/Programs/` | Amcache / AppCompat |
| `$Recycle.Bin/` | Recycle Bin metadata |

**Deleted file recovery:** unallocated space carved by `tsk_recover`.

---

## Output Structure

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
├── result_tsk_recover/      # carved deleted files
├── md5sum.txt
├── tsk_recover.log
└── forensic_collector.log
```

---

## Workflow

1. Check required tools
2. Create case directory structure
3. Calculate MD5 of the evidence image
4. Auto-convert non-raw images if needed (VMDK, VHD, qcow2…)
5. Display `mmls` partition layout — select Windows partition (or use `-o` to skip)
6. Detect BitLocker encryption
7. Extract `$MFT` and `$LogFile` by fixed NTFS inode
8. Build full filesystem listing once with `fls -r -p`
9. Extract individual files in parallel (`-j` workers)
10. Extract directory collections in parallel
11. Run `tsk_recover` concurrently in the background
12. Generate a summary report with MD5 count
