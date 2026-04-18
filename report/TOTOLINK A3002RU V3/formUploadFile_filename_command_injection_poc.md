# PoC Notes - formUploadFile Command Injection

## Endpoint
POST /boafrm/formUploadFile

## Input Vector
multipart filename field

## Verification Goal
Confirm that filename is used without sanitization in command construction.

## What to Check
- Extracted filename value
- Command string before system()
- Behavior difference between normal and special-character filename

## Expected Observation
- filename directly embedded in command string
- No escaping or filtering applied
- Command string structure altered by special characters
