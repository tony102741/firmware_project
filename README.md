# Firmware Vulnerability Analysis Pipeline

Static analysis tooling for finding potentially exploitable issues in firmware
images. The repository intentionally tracks only source code and lightweight
project metadata.

## What It Does

- Extracts supported firmware images, including Android OTA archives and common
  IoT firmware bundles.
- Identifies web-exposed surfaces such as `/www` and `/cgi-bin`.
- Tracks user-controlled input toward sensitive sinks such as `system`, `exec`,
  and `popen`.
- Checks reachability and filters out obvious non-controllable flows.
- Writes structured candidate results for manual review.

## Repository Layout

```text
src/              Python source code
.gitignore        Local artifact and secret ignore rules
README.md         Project overview
requirements.txt  Python dependency list
```

Large local inputs, extracted files, tool downloads, run outputs, caches, and
research notes are intentionally ignored.

## Requirements

- Python 3
- git
- go
- binwalk
- unzip
- p7zip

Install Python dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run a dry check:

```bash
python3 src/pipeline.py --dry-run
```

Analyze a firmware image:

```bash
python3 src/pipeline.py --input <firmware>
```

Check local pipeline state:

```bash
python3 src/pipeline.py --status
```

Clean local generated artifacts:

```bash
python3 src/pipeline.py --cleanup build rootfs
python3 src/pipeline.py --retain-runs 5 --retain-extracted 2
```

## Local Files

Keep firmware samples and generated outputs outside Git. The `.gitignore` file
already excludes common local-only paths such as `inputs/`, `runs/`, `.cache/`,
`research/`, `report/`, `tools/`, and virtual environments.

## Output Example

```text
endpoint: /cgi-bin/example.cgi
param: cmd
flow: QUERY_STRING -> system()
```

## Limitations

- Some vendor firmware may require custom extraction.
- Encrypted firmware is not supported.
- Results still require manual validation before treating them as confirmed
  vulnerabilities.

## License

MIT License
