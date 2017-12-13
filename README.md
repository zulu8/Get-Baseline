# Get-Baseline

Get-Baseline is a wrapper PowerShell script for a number of functions that automates the initial tasks in an incident response scenario. 

## Features

### Remote Access

**Enable PSRemoting for systems in scope.**

#### `Enable-RemoteAccess`

Enable PowerShell Remoting / WinRM via SMB (PsExec) or WMI (Invoke-WmiMethod)

#### `Enable-WinRMPsExec`

Enable PowerShell Remoting / WinRM via SMB (PsExec)

#### `Enable-WinRMWMI`

Enable PowerShell Remoting / WinRM via WMI (Invoke-WmiMethod)

### Baseline Collection

**Collect ASEPs, live process, configuration data for systems in scope.**

#### `Get-BetterTasklist`

Collects current running processes - TimeGenerated, Name, ProcessID, ParentProcessId, ExecutablePath, Hash, CommandLine

#### `Get-DLLs`

Collects current loaded DLLs - TimeGenerated, ModuleName, FileName, Hash, Size, Company, Description, FileVersion, Product, ProductVersion

#### `Get-BetterNetstat`

Collects current netstat output - TimeGenerated, Protocol, LocalAddress, ForeignAddress, State, Name, ProcessId, ParentProcessId, ExecutablePath, Hash, CommandLine 

#### `Invoke-Autorunsc`

Download and execute autorunsc.exe with the following arguments: -accepteula -h -c -nobanner -a * -s

#### `Invoke-Sigcheck`

Verifies signature integrity on the system based on Matt Graeber's "Subverting Trust in Windows" then downloads and executes sigcheck.exe -accepteula -c -u -e -s -r -nobanner C:\Windows\System32 and C:\Windows\SysWOW64

#### `Get-AuditOptions`

Checks registry for additional auditing options - Process Creation Command Line, PowerShell Transcription, PowerShell Script Block Logging, PowerShell Module Logging, Windows Event Forwarding.

## Event Log Collection

**Collect security-relevant event logs for input into SIEM.**

#### `Get-HuntData`

Collects Windows Event Log data from the following Logs:
* Application
* System
* Security
* Windows PowerShell
* Microsoft-Windows-Windows Defender/Operational
* Microsoft-Windows-AppLocker/EXE and DLL
* Microsoft-Windows-AppLocker/MSI and Script
* Microsoft-Windows-AppLocker/Packaged app-Execution
* Microsoft-Windows-DeviceGuard/Operational
* Microsoft-Windows-PowerShell/Operational
* Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
* Microsoft-Windows-Sysmon/Operational

## Prerequisites

On Targets:
* Accessible via WinRM, SMB, or WMI (WinRM Preferred)
* PowerShell 2.0+ (3.5+ Preferred)

On Collection System:  
* PowerShell 5.0+
* Domain Joined
* Logged in with rights as Administrator (able to execute code remotely)


## Usage

```
PS> Get-Baseline -Targets dc01,srv01,srv02,pc02win10 -url "http://10.0.0.128:8080/" -SkipSigcheck
```

```
PS> Get-Baseline -Targets $(get-content <IP_list_file.txt) -url "http://10.0.0.128:8080/" -SkipSigcheck
```


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments
