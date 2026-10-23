# Forensic Scripts

> Open-source forensic tools for Windows artifact collection, Apache log analysis, and MFT triage.

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/bash-4.0%2B-informational?logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

---

## Tools

| Tool | Language | Description |
|------|----------|-------------|
| [forensic-collector](forensic-collector/) | Bash | Extracts Windows artifacts from disk images via SleuthKit |
| [apache2time](apache2time/) | Python 3 | Converts Apache logs to Timesketch import format (JSONL / CSV) |
| [mft-analyzer](mft-analyzer/) | Python 3 | Desktop GUI for triaging `$MFT` exports produced by MFTECmd |

Each tool is self-contained — see its own `README.md` for full usage and options.

---

## Quick Start

### Forensic Collector

> Requires **SleuthKit** (`sudo apt-get install sleuthkit` on Debian / Ubuntu / WSL).

```bash
chmod +x forensic-collector/Forensic_Collector_Win.sh

# Interactive — prompts for all inputs
./forensic-collector/Forensic_Collector_Win.sh

# Non-interactive
./forensic-collector/Forensic_Collector_Win.sh \
  -d "Case_2024_001" -e "/mnt/evidence/disk.dd" -o 2048 -j 8
```

### Apache → Timesketch

> No third-party dependencies.

```bash
python apache2time/apache2time.py /var/log/apache2/ \
  -o web01.jsonl --auto-tag --dedup --tz "+02:00"
```

### MFT Analyzer

> Requires **Python 3.8+** with Tkinter and `duckdb`.

```bash
pip install -r mft-analyzer/requirements.txt
python mft-analyzer/mft_analyzer.py [path/to/mft.csv]
```

Tkinter is not pip-installable — see [mft-analyzer/README.md](mft-analyzer/README.md#requirements) for platform-specific instructions.

---

## Repository Layout

```
Forensic-Scripts/
├── forensic-collector/
│   ├── Forensic_Collector_Win.sh   # artifact extraction script
│   └── README.md
├── apache2time/
│   ├── apache2time.py              # log converter
│   └── README.md
└── mft-analyzer/
    ├── mft_analyzer.py             # DuckDB data layer + Tkinter GUI
    ├── config.py                   # tunable settings
    ├── requirements.txt
    └── README.md
```

---

## License

[GNU General Public License v3.0](LICENSE)
