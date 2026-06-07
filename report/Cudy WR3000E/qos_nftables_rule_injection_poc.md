# PoC Notes - QoS nftables Rule Injection

## Component
QoS (nft-qos)

## Input Source
User-defined service/port values

## Verification Goal
Confirm input affects nftables rule generation.

## What to Check
- /etc/config/nft-qos content
- Generated nft script
- Final applied rules

## Expected Observation
- Input directly reflected in rule string
- No strict validation
- Unexpected rule structures possible
