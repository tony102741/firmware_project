# PoC Notes - formWsc peerRptPin Command Injection

## Endpoint
POST /boafrm/formWsc

## Parameters
- setRptPIN
- peerRptPin

## Verification Goal
Confirm peerRptPin reaches system() without validation.

## What to Check
- Raw POST value extraction
- snprintf command construction
- system() invocation

## Expected Observation
- peerRptPin directly inserted into command string
- No validation path (unlike peerPin/localPin)
- Command structure changes with special characters
