# Japanese Filename Encoding Detector and Fixer

A Python tool to detect and fix Japanese filename encoding issues, particularly useful for files that have encoding conversion problems between different character encodings (e.g., Shift-JIS, EUC-JP, UTF-8).

## Features

- Detects files and directories with potential Japanese encoding issues
- Supports multiple encoding conversion pairs (Shift-JIS, EUC-JP, UTF-8, etc.)
- Uses advanced Japanese text analysis with multiple tokenizers (Fugashi, Sudachi)
- Provides confidence scores for suggested filename corrections
- Supports automatic renaming with backup and recovery options
- Generates detailed scan reports
- Multi-threaded scanning for better performance

## Prerequisites

The following dependencies should already be installed:
- fugashi[unidic]
- sudachipy
- sudachidict_core
- unidic-lite
- jamdict

## Installation

1. Clone the repository
2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python invalid_codec_dic.py [path]
```

Options:
- `path`: Directory to scan (default: current directory)
- `-c, --confidence`: Minimum confidence threshold (0-1, default: 0.5)
- `--auto-rename`: Automatically rename detected files
- `--force`: Force convert all filenames to Japanese, ignore confidence check
- `--recovery`: Specify rename log file path
- `--reverse`: Undo rename operations using the log file

Examples:
```bash
# Scan current directory
python invalid_codec_dic.py

# Scan specific directory with higher confidence threshold
python invalid_codec_dic.py /path/to/directory -c 0.7

# Auto-rename files with encoding issues
python invalid_codec_dic.py --auto-rename

# Undo rename operations
python invalid_codec_dic.py --recovery rename_logs_20241128_123456/rename_history.txt --reverse
```

## Output

The tool generates:
- Scan report with detailed analysis of detected files
- Operation logs for debugging
- Rename history (if auto-rename is enabled)

All output files are saved in timestamped directories:
- `encoding_scan_results_YYYYMMDD_HHMMSS/`
- `rename_logs_YYYYMMDD_HHMMSS/`

## Features in Detail

### Encoding Detection
- Supports multiple encoding conversion pairs
- Uses advanced heuristics for Japanese text detection
- Calculates confidence scores based on multiple features

### Text Analysis
- Morphological analysis using Fugashi
- Token analysis using Sudachi
- Pattern matching for Japanese filename conventions
- Character distribution analysis

### Safety Features
- Backup of renamed files
- Recovery option for rename operations
- Unique filename generation to prevent overwrites
- Detailed logging of all operations

## Note

This tool is specifically designed for Japanese text and may not work well with other languages. It's recommended to review the scan results before applying any automatic renaming.

## Requirements

See requirements.txt for detailed package requirements.
