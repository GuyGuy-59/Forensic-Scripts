# MFT Analyzer


A desktop GUI for triaging NTFS `$MFT` exports produced by [MFTECmd](https://github.com/EricZimmerman/MFTECmd) (Eric Zimmerman).

It indexes the CSV into [DuckDB](https://duckdb.org/) once, so you can filter, sort, page through and export millions of MFT records instantly. You can also build MACB timelines and use a heuristic score to spot possible data staging and exfiltration.

> **Disclaimer:** the exfiltration score is a triage aid, not evidence. Always corroborate findings with other artefacts (`$UsnJrnl`, `$LogFile`, USB/network artefacts, execution logs, etc.).

---

## Features

- **Fast on large MFTs**: the CSV is ingested once into a cached `.duckdb` file. Later loads of the same file are almost instant, and every query runs in SQL, so the full dataset is never held in Python memory.
- **Filters**
  - file name (substring), extensions (comma-separated list)
  - parent folder: *contains*, *subtree* or *exact* match, with a searchable folder picker
  - directories, deleted entries (`InUse=False`), Alternate Data Streams, DOS 8.3 short names
  - date range on last access and/or last modification (UTC)
  - forensic flags: `SI<FN` (timestomping hint), `uSecZeros`, `Copied`, Mark of the Web (`Zone.Identifier`)
- **Results table** with server-side paging, click-to-sort columns and colour-coded rows
- **Computed columns**: created→accessed, created→modified and modified→accessed deltas
- **Detail view** (double-click or Enter on a row): every attribute of the record, plus a line-by-line breakdown of its exfiltration score
- **MACB timeline** of the current selection. Events that share a timestamp are merged into a single row (e.g. `M.CB`). You can view it in the app or export it in full to CSV.
- **Statistics**: counts of deleted entries, ADS, timestomping hints and MOTW, total size, top extensions, time span, and high-score counts
- **Score histogram** (optional, needs matplotlib), exportable as PNG/PDF/SVG/JPEG or CSV
- **CSV export** of the filtered and sorted results

### Row colours

| Colour | Meaning |
|---|---|
| Purple | Exfiltration score ≥ 6 (only when the score is displayed) |
| Red | Deleted entry (`InUse=False`) |
| Orange | Timestomping hint (`SI<FN`) |
| Blue | Has / is an Alternate Data Stream |

---

## Requirements

- Python 3.8+ **with Tkinter**
- [`duckdb`](https://pypi.org/project/duckdb/)
- [`matplotlib`](https://pypi.org/project/matplotlib/) *(optional, only for the histogram)*

```bash
pip install -r requirements.txt
```

**Tkinter notes**
- **Windows:** when installing Python from python.org, keep *"tcl/tk and IDLE"* checked. If it is missing, run the installer again and choose *Modify*.
- **Debian/Ubuntu:** `sudo apt install python3-tk`
- **Arch Linux:** `sudo pacman -S tk python-duckdb python-matplotlib`
- **macOS (Homebrew):** `brew install python-tk`

---

## Usage

### 1. Export the MFT with MFTECmd

```powershell
MFTECmd.exe -f "E:\C\$MFT" --csv "C:\cases\case01" --csvf mft.csv
```

### 2. Open it in MFT Analyzer

```bash
python mft_analyzer.py                         # then use "Browse..."
python mft_analyzer.py C:\cases\case01\mft.csv # load on startup
```

The first load indexes the CSV, which can take from a few seconds to a few minutes depending on its size. After that, the same file opens from cache.

### Cache location

The index is saved as `<csv name>.mft.duckdb` **next to the CSV**. If that folder is not writable (for example, evidence mounted read-only), it goes in `~/.cache/mft_analyzer/` instead.

The cache is rebuilt automatically when the CSV's path, size or modification time changes. You can also rebuild it by ticking **Force re-index** before you click **Load**.

### Date filter syntax

`YYYY-MM-DD`, `YYYY-MM-DD HH:MM` or `YYYY-MM-DD HH:MM:SS`, interpreted as **UTC** (MFTECmd timestamps are UTC). An end date given without a time covers the whole day. When both *Last access* and *Last modified* are ticked, an entry matches if **either** timestamp falls in the range.

---

## Exfiltration score

Each entry gets a heuristic score from 0 to 10. It is designed to bring likely **staging** activity to the top of the list. Staging means files gathered into a folder, often archived, then removed. The strongest signal is temporal clustering across a folder, not any single indicator on one file.

| Indicator | Points |
|---|---|
| **Staging folder (strong):** the parent folder holds ≥ 5 entries created within 5 minutes, and their original modification dates span ≥ 30 days | +4 |
| **Staging folder (weak):** same as above with ≥ 3 entries | +2 |
| Archive/container extension (`zip rar 7z tar gz tgz bz2 xz iso`) | +2 |
| Archive deleted after use (`InUse=False`) | +2 |
| Typical staging location (path contains `temp`, `appdata`, `downloads`, `programdata`) | +1 |
| Recent copy of an old file (`Created − LastModified ≥ 30 days`) | +1 |

The total is capped at 10. All thresholds and weights live in [`config.py`](config.py), so you can adjust them to your case (see [Configuration](#configuration)).

Expect false positives: software updates, browser caches and installers often look like staging.

---

## Configuration

All settings are in `config.py`:

| Section | What you can change |
|---|---|
| Schema | Which CSV columns are read as booleans, timestamps or integers |
| Display | Default columns, column widths, row colours, page size, accepted date formats |
| Computed columns | Delta columns (SQL expressions) and the score column name |
| MACB timeline | Timestamp → M/A/C/B mapping, context columns, on-screen event limit |
| Exfiltration score | Archive extensions, staging keywords, time thresholds, points per indicator |

Score and display changes apply the next time you start the tool. Changes to the schema lists also re-index cached files automatically on the next load.

---

## Project layout

```
mft_analyzer.py   # application: DuckDB data layer (MFTStore) + Tkinter GUI
config.py         # tunable settings
requirements.txt
```

---

## Expected CSV columns

The tool targets the standard MFTECmd `$MFT` CSV output. It adapts to the columns it finds, and any feature whose columns are missing is simply disabled. The main columns used are:

`EntryNumber`, `SequenceNumber`, `InUse`, `ParentPath`, `FileName`, `Extension`, `FileSize`, `IsDirectory`, `HasAds`, `IsAds`, `SI<FN`, `uSecZeros`, `Copied`, `NameType`, `ZoneIdContents`, and the `Created` / `LastModified` / `LastRecordChange` / `LastAccess` timestamps (`0x10` and `0x30`).

---

## Limitations

- Timestamps are truncated to microseconds (MFTECmd writes 100 ns precision).
- The on-screen MACB timeline shows the first 5,000 events. Use **Export full timeline** to get all of them.
- The score uses `$STANDARD_INFORMATION` (`0x10`) timestamps, which can be modified by timestomping. Check the `SI<FN` flag and the `0x30` timestamps when it matters.
