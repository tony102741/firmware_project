# Validation Notes - ipTIME AX3000M Hidden Diagnostic CGI

## Target

- product:
  - `ipTIME AX3000M`
- versions:
  - `14.234`
  - `15.024`
  - `15.330`

## Relevant Files

- `14.234`
  - `cgibin/timepro.cgi`
- `15.024`
  - `home/httpd/cgi/d.cgi`
- `15.330`
  - `home/httpd/cgi/ftm.cgi`

## Verification Goal

Confirm the hidden diagnostic interface structurally without using live
exploitation steps.

## What To Check

### `14.234`

- `timepro.cgi` dispatcher contains:
  - `"/cgibin/d.cgi"`
- hidden diagnostic fields are present:
  - `fname`
  - `cmd`
  - `aaksjdkfj`
- dispatcher forwards to the hidden diagnostic handler family

### `15.024`

- `d.cgi` contains hidden diagnostic form strings
- auth / csrf / hidden-gate checks are present
- user-controlled command data reaches:
  - `popen(...)`

### `15.330`

- `d.cgi` is absent
- `ftm.cgi` handles factory-test mode only
- no equivalent generic `cmd -> popen()` path is present

## Expected Observation

- `14.234` / `15.024`
  - hidden diagnostic/debug interface exists
  - generic command-capable path exists
- `15.330`
  - earlier interface is removed or restricted
  - replacement behavior is fixed-operation factory-test control

## Safe Interpretation

The intended validation result is:

- older firmware contains a concealed diagnostic interface with generic
  command-execution capability
- newer firmware no longer exposes the same visible path and instead keeps only
  a restricted factory-test operation flow

No exploit payloads or reproduction procedure are required to support this
structural conclusion.
