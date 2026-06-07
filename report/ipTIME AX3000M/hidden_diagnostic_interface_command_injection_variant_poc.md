# PoC Notes - ipTIME AX3000M Hidden Diagnostic Interface Command Injection Variant

## Vulnerability Class
Hidden Diagnostic CGI Command Injection Variant

## Known Reference
- `CVE-2025-14485`
- `ipTIME A3004T`
- `timepro.cgi`

## Affected Product
- `ipTIME AX3000M`

## Affected Versions
- `14.234`
- `15.024`
- `15.330` is the patched / restricted comparison point

## Relevant Files
- `14.234`
  - `cgibin/timepro.cgi`
- `15.024`
  - `home/httpd/cgi/d.cgi`
- `15.330`
  - `home/httpd/cgi/ftm.cgi`

---

## Step 1: Variant Family Confirmation

### What to Check
- same hidden parameter name:
  - `aaksjdkfj`
- same diagnostic family:
  - `timepro.cgi`
  - `d.cgi`
- same execution sink family:
  - `popen(...)`

### Expected Observation
- AX3000M matches the same hidden diagnostic command-execution family as the
  published ipTIME reference issue

---

## Step 2: AX3000M Command Path Reconstruction

### What to Check
- hidden diagnostic route exists
- `cmd` is read from CGI input
- static gate is checked
- command string reaches `popen(...)`

### Minimal Chain
```text
HTTP request
 -> hidden diagnostic CGI
 -> auth / csrf / static gate
 -> get_value("cmd")
 -> append " 2>&1"
 -> popen(command, "r")
```

### Expected Observation
- attacker-controlled command data is passed to shell execution sink
- no escaping or allowlist is present before `popen`

---

## Step 3: Static Gate Weakness

### What to Check
- parameter name:
  - `aaksjdkfj`
- literal gate value is hardcoded in the binary
- value is not device-unique

### Gate Value
```text
!@dnjsrurelqjrm*&
```

### Expected Observation
- the gate functions as a hidden debug unlock token, not real access control

---

## Step 4: Version-Diff Confirmation

### What to Check

#### `14.234`
- `timepro.cgi` dispatches hidden `/cgibin/d.cgi`
- diagnostic form fields include `cmd`, `fname`, `aaksjdkfj`

#### `15.024`
- standalone `d.cgi` preserves the same command-execution behavior

#### `15.330`
- old `d.cgi` path is gone
- `ftm.cgi` exposes only fixed factory-test behavior
- no generic `cmd -> popen()` path remains

### Expected Observation
- earlier versions are vulnerable
- later version reflects removal or restriction of the diagnostic path

---

## Step 5: Classification Check

### What to Compare Against `CVE-2025-14485`
- same vendor family
- same hidden diagnostic concept
- same `aaksjdkfj` parameter family
- same command-execution sink family
- different model and firmware layout

### Expected Observation
- this should be classified as an AX3000M variant, not an unrelated new design

---

## Verification Goal

Confirm the following structural conclusion:

- AX3000M `14.234` and `15.024` contain a concealed diagnostic command
  execution path
- the command sink is attacker-influenced through `cmd`
- the gate is a hardcoded, firmware-recoverable static secret
- `15.330` removes or restricts the prior path
- the issue is best framed as an AX3000M variant of the published
  `CVE-2025-14485` family
