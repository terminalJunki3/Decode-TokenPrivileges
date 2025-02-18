<#
.SYNOPSIS
    Decodes a token privileges bitmask and displays detailed mapping and explanation.

.DESCRIPTION
    This script accepts a decimal value representing a token privileges bitmask. It performs the following:

      1. Dynamically looks up the LUID for each known Windows privilege via LookupPrivilegeValue.
      2. Computes the corresponding bit mask for each privilege using (1 << LUID.LowPart).
      3. Displays the conversion of the provided token privileges value from decimal to hexadecimal and binary.
      4. Presents a detailed table showing:
            - The privilege name.
            - Its LUID (LowPart and HighPart).
            - The computed bit mask (in hexadecimal).
            - Whether that privilege is enabled in the provided bitmask.
      5. Provides an “Explanation” section that helps you see how the bit index (from LUID.LowPart)
         maps to a bit in the binary representation.
      6. Lists only the enabled privileges below the table.

    Note:
      - The rightmost bit in the binary representation is bit index 0.
      - For example, if a privilege has LUID.LowPart = 3, then its mask is (1 << 3) = 0x8.
        In the binary representation (displayed as 64 bits), the fourth bit from the right should be set.

.PARAMETER DecimalValue
    The decimal value representing the token privileges bitmask.
    (Example: 8008056)

.EXAMPLE
    PS C:\> .\Decode-TokenPrivileges.ps1 -DecimalValue 8008056

.NOTES
    The script uses P/Invoke to call the Windows API (advapi32.dll) for dynamic lookup of privilege LUIDs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
               HelpMessage = "Enter the decimal token privileges value (e.g. 8008056)")]
    [UInt64]$DecimalValue
)

#----------------------------------------------------------------------------
# Add P/Invoke definitions for LookupPrivilegeValue from advapi32.dll
#----------------------------------------------------------------------------
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
}
[StructLayout(LayoutKind.Sequential)]
public struct LUID {
    public uint LowPart;
    public int HighPart;
}
"@ -ErrorAction Stop

#----------------------------------------------------------------------------
# Function: Get-LuidFromPrivilege
#
# Uses LookupPrivilegeValue to retrieve the LUID for a given privilege name.
# Returns $null if the privilege isn’t defined on this system.
#----------------------------------------------------------------------------
function Get-LuidFromPrivilege {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrivilegeName
    )
    $luid = New-Object "LUID"
    $result = [Advapi32]::LookupPrivilegeValue($null, $PrivilegeName, [ref]$luid)
    if (-not $result) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "LookupPrivilegeValue failed for $PrivilegeName. Error code: $err"
        return $null
    }
    return $luid
}

#----------------------------------------------------------------------------
# Define the full list of known privileges.
#----------------------------------------------------------------------------
$PrivilegeList = @(
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemProfilePrivilege",
    "SeSystemtimePrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeDebugPrivilege",     
    "SeAuditPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeTrustedCredManAccessPrivilege",
    "SeRelabelPrivilege",
    "SeIncreaseWorkingSetPrivilege"
)


#----------------------------------------------------------------------------
# Build a dynamic mapping and detailed table of privilege data.
#
# For each privilege, look up its LUID, calculate the corresponding bit mask (1 << LUID.LowPart),
# and determine if that bit is set in the provided DecimalValue.
#----------------------------------------------------------------------------
$MappingDetails = @()

foreach ($priv in $PrivilegeList) {
    $luid = Get-LuidFromPrivilege -PrivilegeName $priv
    if ($luid -ne $null) {
        $bitIndex = $luid.LowPart
        $mask = [UInt64]1 -shl $bitIndex
        $enabled = (($DecimalValue -band $mask) -eq $mask)
        $MappingDetails += [PSCustomObject]@{
            "Privilege"     = $priv
            "LUID_LowPart"  = $luid.LowPart
            "LUID_HighPart" = $luid.HighPart
            "BitMaskHex"    = ("0x{0:X16}" -f $mask)
            "Enabled"       = $enabled
        }
    }
    else {
        Write-Verbose "Privilege $priv is not defined on this system."
    }
}

#----------------------------------------------------------------------------
# Display conversion of the provided value: Decimal -> Hexadecimal -> Binary
#----------------------------------------------------------------------------
$hexValue = "{0:X16}" -f $DecimalValue
$binaryValue = [Convert]::ToString($DecimalValue, 2).PadLeft(64, '0')

Write-Host "Decoding Token Privileges for Decimal Value: $DecimalValue" -ForegroundColor Cyan
Write-Host "Hexadecimal Representation: $hexValue" -ForegroundColor Cyan
Write-Host "Binary Representation: $binaryValue" -ForegroundColor Cyan
Write-Host "-----------------------------------`n"

#----------------------------------------------------------------------------
# Display detailed mapping table.
#----------------------------------------------------------------------------
Write-Host "Detailed Privilege Mapping:" -ForegroundColor Yellow
$MappingDetails | Sort-Object LUID_LowPart | Format-Table -AutoSize
Write-Host ("`nNote: 'BitMaskHex' is computed as (1 << LUID.LowPart).") -ForegroundColor DarkCyan
Write-Host ("The binary representation is 64 bits (bit positions 63 to 0), with the rightmost bit as bit index 0.") -ForegroundColor DarkCyan
Write-Host ("For example, if LUID.LowPart is 3, then (1 << 3) is 0x8. That means the 4th bit from the right should be '1'") -ForegroundColor DarkCyan
Write-Host ("in the binary representation if the privilege is enabled.") -ForegroundColor DarkCyan
Write-Host ""

#----------------------------------------------------------------------------
# (Optional) Display a focused view of the lower 32 bits with bit positions.
#----------------------------------------------------------------------------
$lower32 = $binaryValue.Substring(32,32)
# Build an index ruler for the lower 32 bits (bit indices 31 to 0)
$indices = (31..0 | ForEach-Object { "{0,2}" -f $_ }) -join " "
Write-Host "Lower 32 bits (bit positions 31 to 0):"
Write-Host $indices
Write-Host $lower32
Write-Host ""

#----------------------------------------------------------------------------
# List only the enabled privileges.
#----------------------------------------------------------------------------
$EnabledPrivileges = $MappingDetails | Where-Object { $_.Enabled -eq $true }

if ($EnabledPrivileges) {
    Write-Host "Enabled Privileges:" -ForegroundColor Green
    foreach ($entry in $EnabledPrivileges | Sort-Object LUID_LowPart) {
        Write-Host (" - {0} (Bit index: {1}, Mask: {2})" -f $entry.Privilege, $entry.LUID_LowPart, $entry.BitMaskHex)
    }
}
else {
    Write-Host "No privileges are enabled in the provided token privileges value." -ForegroundColor Red
}

#----------------------------------------------------------------------------
# Explanation Section
#----------------------------------------------------------------------------
Write-Host ("`n=== Explanation ===") -ForegroundColor Magenta
Write-Host ("The binary representation of the token privileges value is shown above (64 bits).") -ForegroundColor Magenta
Write-Host ("Each privilege is assigned a bit position based on its LUID.LowPart.") -ForegroundColor Magenta
Write-Host ("For instance, a privilege with LUID.LowPart = 3 has a bit mask of (1 << 3) = 0x0000000000000008.") -ForegroundColor Magenta
Write-Host ("In the binary string, count from the right (bit index 0) to verify:") -ForegroundColor Magenta
Write-Host (" - The rightmost bit is index 0, the next is index 1, and so on.") -ForegroundColor Magenta
Write-Host ("Thus, if the bit at index 3 is '1', the privilege with LUID.LowPart = 3 is enabled.") -ForegroundColor Magenta
Write-Host ("Refer to the 'Detailed Privilege Mapping' table to see which privilege corresponds to which bit.") -ForegroundColor Magenta
