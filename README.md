# Decoding Windows Token Privileges

This PowerShell script decodes a single decimal value—representing the enabled privileges in a Windows token—into a detailed list of actual privileges.

## Use Case

Often, security logs (e.g., from Sentinel) provide a key like `currenttokenprivenabled` with a decimal value. This script helps convert that value into the actual privileges that are enabled, making it easier to audit or analyze token privileges.

## Overview

Windows tokens store privileges as an array of **LUID_AND_ATTRIBUTES** structures, not as a single bitmask. However, many tools derive a bitmask representation by computing each privilege's mask as `(1 << LUID.LowPart)`. This script:

- Dynamically queries Windows for each privilege's LUID via the **LookupPrivilegeValue** API.
- Computes a bitmask for each privilege.
- Compares the computed bitmask with the provided decimal value to determine which privileges are enabled.
- Displays detailed information including the privilege name, LUID (LowPart and HighPart), computed bitmask (in hexadecimal), and enabled status.

## How to Use

1. Open PowerShell.
2. Run the script with the decimal value as a parameter. For example:

   ```powershell
   .\Decode-TokenPrivileges.ps1 -DecimalValue 8008056
   ```

## Review the Output

- **Detailed Privilege Mapping**: A table listing each privilege, its LUID, computed bitmask, and whether it’s enabled.
- **Enabled Privileges**: A list of privileges determined to be enabled based on the input value.

## Important Notes

### Derived Representation

The bitmask representation `(1 << LUID.LowPart)` is a derived convention and not the native storage format in Windows.

### Consistency Across Systems

The script uses the system’s API to retrieve current LUIDs for privileges. For accurate mapping, it's best to run the script on the same or an identical Windows environment that generated the token value.

## Official References

- [TOKEN_PRIVILEGES structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)
- [LUID_AND_ATTRIBUTES structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes)
- [LookupPrivilegeValue function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea)

## Red Team / Blue Team Applications

- **Red Teams**: Identify enabled privileges to determine potential paths for escalation or lateral movement.
- **Blue Teams**: Audit token privileges to detect anomalous or unauthorized privileges.

