# Firmware Vulnerability Analysis Pipeline

A static analysis pipeline for identifying **potentially exploitable vulnerabilities** in firmware images.

---

## Overview

Traditional static analysis often produces many candidates that are not practically exploitable.

This project focuses on reducing false positives by analyzing:

* Web-exposed components
* Data flow from user input to sensitive functions
* Realistic reachability from external interfaces

---

## Features

### 1. Firmware Extraction

* Android OTA (`.zip`)
* IoT firmware (`.bin`)
* Uses `payload-dumper-go` and `binwalk`

---

### 2. Web Surface Identification

* Detects web entry points:

  * `/www`
  * `/cgi-bin`
* Maps HTTP requests to underlying binaries

---

### 3. Data Flow Analysis

Tracks flow from user input to sensitive functions:

* `system`
* `exec`
* `popen`

---

### 4. Flow Verification

Filters out:

* constant execution
* non-controllable inputs

Keeps only flows where user input reaches a sink.

---

### 5. Reachability Check

Determines:

* whether the path is remotely accessible
* whether authentication is required
* how input is controlled

---

### 6. PoC Generation

Outputs simple request examples when applicable:

```bash
curl "http://target/cgi-bin/xxx?cmd=id"
```

---

## Pipeline

```
Firmware
 → Extraction
 → Web surface analysis
 → Data flow tracking
 → Flow verification
 → Reachability check
 → Candidate output
```

---

## Requirements

```bash
python3
binwalk
unzip
p7zip
```

---

## Usage

```bash
python3 src/pipeline.py --input <firmware>
```

---

## Output Example

```
endpoint: /cgi-bin/example.cgi
param: cmd
flow: QUERY_STRING → system()
```

---

## Limitations

* Some vendor firmware may require custom extraction
* Encrypted firmware is not supported
* No dynamic execution validation

---

## License

MIT License
