# PoC Notes - Repeater SSID Command Injection

## Input Source
External SSID (Site Survey)

## Verification Goal
Confirm SSID propagates into system() command.

## What to Check
- SSID storage via apmib_set
- Retrieval via apmib_get
- Command construction using sprintf

## Expected Observation
- SSID value preserved across layers
- Partial escaping only
- Certain characters remain unescaped and affect command string
