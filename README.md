# Tamper-Evident Logging System

A cryptographically chained logging system where any modification, deletion, or reordering of log entries is immediately detected. Built in Python using SHA-256 hashing and SQLite.

The system also includes a log normalization module that reads real world log files from different operating systems and formats, normalizes them into a standard structure, and chains them into the tamper-evident database automatically.

## What it does

- Every log entry is hashed and linked to the previous entry — like a blockchain
- If anyone modifies, deletes, or reorders an entry, the chain breaks and verification catches it immediately
- Pinpoints the exact entry where tampering occurred
- Imports real world log files from 6 different formats and normalizes them automatically

## Supported Log Formats for Import

| Format | Example Source |
|---|---|
| SSH Auth Log | OpenSSH syslog — `/var/log/auth.log` |
| Windows Event Log | Windows CBS/component log |
| Apache Access Log | Apache HTTP server access log |
| Apache Error Log | Apache HTTP server error log |
| Linux Syslog | Linux system log — `/var/log/syslog` |
| macOS ASL | macOS system log |

## Requirements

```
hashlib
sqlite
datetime
re
```

All these are standard python libraries.

## How to run

```
python temper_evident.py
```

## Menu Options

```
1. Add log entry          — manually add a new event to the chain
2. Show all entries       — display all logs in the database
3. Verify chain integrity — check the entire chain for tampering
4. Simulate tampering     — modify an entry without updating its hash
5. Simulate deletion      — delete a middle entry from the chain
6. Simulate reorder       — swap two entries to simulate reordering
7. Import logs            — import a real world log file and chain it
8. Exit
```

## How to import real world logs

There are logs present in the Logs folder with 2000 entries in each file.

if you want to increase the log size

Put your log files in a `logs/` folder in the same directory, then run the program and pick option 7:

```
Enter log file path: logs/auth.log
```

The system will automatically detect the format, normalize each line, and chain it into the database. Unrecognized lines are skipped and reported.

## How tamper detection works

Each log entry stores:
- Its own content — timestamp, event type, description
- The hash of the previous entry — `prev_hash`
- Its own hash computed from all fields including `prev_hash` — `entry_hash`

This creates a chain where every entry is mathematically dependent on the one before it.

**Modification detected** — the stored hash no longer matches the recomputed hash of that entry.

**Deletion detected** — the `prev_hash` of the next entry no longer matches any existing entry's hash.

**Reordering detected** — the chain order is wrong, causing hash mismatches across multiple entries.

## Project Structure

```
Tamper-Evident-Logging-System/
├── temper_evident.py     — main program, CLI menu, all core functions
├── log_normalizer.py     — log parsing, normalization, import pipeline
├── logs/                 — put your log files here
│   ├── auth.log
│   ├── Windows_2k.log
│   └── Apache_2k.log
└── logs.db               — SQLite database (auto-created on first run)
```

## What I learned building this

This started as a straightforward hashing project and grew into a full log pipeline. I learned how SHA-256 chaining actually works from scratch, how SQLite handles structured security data, how real world log formats differ across operating systems, and how regex is used to parse and normalize unstructured text data.

The normalization module was the biggest challenge as every OS writes logs differently and building a parser for each format taught me a lot about how real SIEM tools work under the hood.

## Sources

- Python hashlib documentation — https://docs.python.org/3/library/hashlib.html
- Python sqlite3 documentation — https://docs.python.org/3/library/sqlite3.html
- LogHub dataset — https://github.com/logpai/loghub
