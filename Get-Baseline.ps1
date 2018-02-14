function Get-Baseline {
	<#
	.SYNOPSIS
	This script is used to get useful baseline information from windows systems in scope.
	It is designed for the Incident Response scenario. It primarily relies on PowerShell 
	Remoting and can enable PSRemoting over SMB or WMI if necessary.
	Function: Get-Baseline
	Author: Jake Van Duyne
	Required Dependencies: 
		-Sysinternals Suite served via http. Update $url variable
		-List hostnames of target systems in Targets array
		-Targets have remote administration enabled - PSRemoting, SMB, or WMI
	Optional Dependencies: None
	Version: 1.0
	.DESCRIPTION
	This script is used to get useful information from a computer. Currently, the script gets the following information:
		-System Information
		-Tasklist
		-Netstat
		-Loaded DLLs
		-Audit Configuration
		-Event Log Configuration
		-Event Log Data
		-Autorunsc
		-SigCheck SysWOW64,System32
	.PARAMETER NoHash
	Bool: Set to $true to skip the hashing function for executables and dlls. Default: $false
	.PARAMETER Targets
	String[]: Comma separated list of hostnames to execute script on.
	Can also be $(get-content <IP_list_file.txt)
	.PARAMETER url
	String: Provide the URL of the Sysinternals Suite http server.
	.EXAMPLE
	PS> Get-Baseline -Targets dc01,srv01,pc02win10 -url "http://10.0.0.133:8080/" -SkipSigcheck
	PS> Get-Baseline -Targets dc01 -url "http://10.0.0.133:8080/" -SkipSigcheck

	.EXAMPLE
	PS> Get-Baseline -Targets $(get-content hostname_list.txt) -url "http://10.0.0.128:8080/" -SkipSigcheck
	.LINK
	#>
	[cmdletbinding()]
	Param([bool] $NoHash = $false,
	[String[]]$Targets,
	[String]$url,
	[Switch]$SkipSystemInfo,
	[Switch]$SkipTasklist,
	[Switch]$SkipDLLs,
	[Switch]$SkipNetstat,
	[Switch]$SkipSigcheck,
	[Switch]$SkipAutoruns,
	[Switch]$SkipAuditConfig,
	[Switch]$SkipEventLogSettings,
	[Switch]$SkipRemoteEnable,
	[Switch]$SkipEventLogData)
	
	$VerbosePreference = "Continue"
	
	Start-Transcript -Path ".\Log_$(get-date -UFormat "%Y%m%d").txt" -Append

	New-Item ./Baseline -type directory -force -EA SilentlyContinue

	# Check All Mandatory Variables and Dependencies
	# Test Sysinternals Suite HTTP Server "url" variable
	$urlp = $url + "PsExec.exe"
	$path = (Get-Location).Path + "\PsExec.exe"
	(New-Object Net.WebClient).DownloadFile($urlp, $path)
	if ( -Not (Test-Path .\PsExec.exe)) {
		Write-Warning "There is something wrong with the -url variable!"
		Stop-Transcript
		continue
	}
	
	# Test local PSVersion (must be greater than 4.0)
	if ( $PSVersionTable.PSVersion.Major -lt 4 ) {
		Write-Warning "The system running this script must have a PSVersion of 4.0 or greater"
		Write-Warning "The remote systems can be as low as 2.0"
		Stop-Transcript
		continue
	}
	

	# Check Targets for Remote Access and Enable.
	if (-Not $SkipRemoteEnable) {	
		$PSTargets = @()
		$PSTargets = Enable-RemoteAccess -Targets $Targets
	} else {
		$PSTargets = $Targets
	}
	Write-Host "Scheduled to execute baseline collection on:"
	Write-Host $PSTargets
	$ExecuteConfirmation = Read-Host "`nAre you sure you want to execute? [y/n]"
	if (($ExecuteConfirmation -eq "n") -OR ($ExecuteConfirmation -eq "N")) {
		continue
	}
	
	# All Parallel Commands
	if (-Not $SkipAuditConfig) {	
		Write-Verbose "Getting Audit Levels"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock {& auditpol /get /category:* /r | Convertfrom-Csv} -ThrottleLimit 5 | Export-Csv ./Baseline/auditpol.csv -NoTypeInformation
		
		Write-Verbose "Getting Additional Audit Options"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-AuditOptions} -ThrottleLimit 5 | Export-Csv ./Baseline/auditoptions.csv -NoTypeInformation
	}
	
	if (-Not $SkipSystemInfo) {
		Write-Verbose "Getting System Information"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock {& systeminfo /FO CSV | Convertfrom-Csv} | Export-Csv ./Baseline/systeminfo.csv -NoTypeInformation
	}
	
	if (-Not $SkipTasklist) {
		Write-Verbose "Getting Better Tasklist"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-BetterTasklist} -ArgumentList $NoHash | Export-Csv ./Baseline/tasklist.csv -NoTypeInformation
	}
	
	if (-Not $SkipDLLs) {
		Write-Verbose "Getting Loaded DLLs"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-DLLs} -ArgumentList $NoHash | Export-Csv ./Baseline/dlls.csv -NoTypeInformation
	}
	
	if (-Not $SkipNetstat) {
		Write-Verbose "Getting Better TCP Netstat"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-BetterNetstatTCP} -ArgumentList $NoHash | Export-Csv ./Baseline/netstat_TCP.csv -NoTypeInformation
	
		Write-Verbose "Getting Better TCPv6 Netstat"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-BetterNetstatTCPv6} -ArgumentList $NoHash | Export-Csv ./Baseline/netstat_TCPv6.csv -NoTypeInformation

		Write-Verbose "Getting Better UDP Netstat"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-BetterNetstatUDP} -ArgumentList $NoHash | Export-Csv ./Baseline/netstat_UDP.csv -NoTypeInformation
		
		Write-Verbose "Getting Better UDPv6 Netstat"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Get-BetterNetstatUDPv6} -ArgumentList $NoHash | Export-Csv ./Baseline/netstat_UDPv6.csv -NoTypeInformation
	}
	
	
	if (-Not $SkipAutoruns) {
		Write-Verbose "Getting Autorunsc Data"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Invoke-Autorunsc} -ArgumentList $url | Export-Csv ./Baseline/autorunsc.csv -NoTypeInformation
	}
	
	
	if (-Not $SkipSigcheck) {
		Write-Verbose "Checking System32 and SysWOW64 for unsigned binaries"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock ${Function:Invoke-Sigcheck} -ArgumentList $url | Export-Csv ./Baseline/sigcheck.csv -NoTypeInformation
	}
	
	
	if (-Not $SkipEventLogSettings) {
		Write-Verbose "Getting Event Log Settings"
		Invoke-Command -ComputerName $PSTargets -ScriptBlock {Get-EventLog -list | Select LogDisplayName,Log,MachineName,MaximumKilobytes,OverflowAction,MinimumRetentionDays,EnableRaisingEvent,SynchronizingObject,Source,Site,Container
		} | Export-Csv ./Baseline/eventloglist.csv -NoTypeInformation
	}
	
	if (-Not $SkipEventLogData) {	
		Get-HuntData -Targets $PSTargets
	} 
	
	Stop-Transcript
}


function Get-HuntData {
	<#
	.SYNOPSIS
	This script queries remote systems for windows event logs.
	Function: Get-HuntData
	Author: 
	Required Dependencies: PSRemoting
	Optional Dependencies: None
	Version: 1.0
	.DESCRIPTION
	Be mindful of size. 313,746 Entries creates a 279 MB CSV...
	Recommend running this script on 5 or fewer targest at a time.
	Also Note that Get-WinEvent requires PowerShell Version 3.5+
	.PARAMETER Verbose
	.PARAMETER Targets
	String[]: Comma separated list of hostnames to execute script on.
	Can also be $(get-content <IP_list_file.txt)
	.EXAMPLE
	PS> Get-HuntData -Targets pc01win7
	.LINK
	#>
	[cmdletbinding()]
	Param([String[]]$Targets)
	
	$VerbosePreference = "Continue"

	New-Item ./EventLogData -type directory -force
	
	foreach ($i in $Targets) {
		
		New-Item ./EventLogData/$i -type directory -force
		
		Write-Verbose "Collecting Application Log on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-EventLog -LogName "Application"} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_application_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting System Log on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-EventLog -LogName "System"} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_system_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Powershell Log on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-EventLog -LogName "Windows PowerShell"} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_powershell_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Microsoft-Windows-Windows Defender/Operational on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_defender_operational_$i`.csv -NoTypeInformation
		
		Write-Verbose "Collecting Microsoft-Windows-AppLocker/EXE and DLL on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_applocker_exedll_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Microsoft-Windows-AppLocker/MSI and Script on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/MSI and Script'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_applocker_msiscript_$i`.csv -NoTypeInformation
		
		Write-Verbose "Collecting Microsoft-Windows-AppLocker/Packaged app-Execution on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/Packaged app-Execution'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_applocker_packaged_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Microsoft-Windows-DeviceGuard/Operational on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-DeviceGuard/Operational'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_deviceguard_operational_$i`.csv -NoTypeInformation
		
		Write-Verbose "Collecting Microsoft-Windows-PowerShell/Operational on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_powershell_operational_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Microsoft-Windows-Windows Firewall With Advanced Security/Firewall on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_firewall_$i`.csv -NoTypeInformation

		Write-Verbose "Collecting Microsoft-Windows-Sysmon/Operational on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_sysmon_operational_$i`.csv -NoTypeInformation
		
		Write-Verbose "Collecting Security Log on $i"
		Invoke-Command -ComputerName $i -ScriptBlock {Get-EventLog -LogName "Security"} -EA SilentlyContinue | Export-Csv ./EventLogData/$i/eventlog_security_$i`.csv -NoTypeInformation
	}
}


function Enable-RemoteAccess {
	[cmdletbinding()]
	Param([String[]] $Targets)
	
	$VerbosePreference = "Continue"
	
	$SMBConfirmation = Read-Host "`n`nIf WinRM/PSRemoting is DISABLED, attempt to ENABLE with PsExec? [y/n]"
	$WMIConfirmation = Read-Host "`nIf WinRM/PSRemoting and SMB is DISABLED, attempt to ENABLE with WMI? [y/n]"
	
	$PSTargets = @()
	$SMBTargets = @()
	$WMITargets = @()
	$NoRemoteTargets = @()
	$SMBChangedTargets = @()
	$SMBFailedTargets = @()
	$WMIChangedTargets = @()
	$WMIFailedTargets = @()
	

	foreach ($i in $Targets) {
		Write-Verbose "Testing Remote Management Options for $i"
		if ( Test-WSMan $i -EA SilentlyContinue ) {
			Write-Verbose "PSRemoting Enabled on $i"
			$PSTargets += $i
		} elseif ( Test-Path \\$i\admin$ -EA SilentlyContinue ) {
			Write-Verbose "SMB Enabled on $i"
			$SMBTargets += $i
		} elseif ( Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "CMD.EXE /c ipconfig" -ComputerName $i -EA SilentlyContinue ) {
			Write-Verbose "WMI Enabled on $i"
			$WMITargets += $i
		} else {
			Write-Verbose "NO REMOTING Enabled on $i"
			$NoRemoteTargets += $i
		}
	}
	
	Write-Host "`n========================================================================"
	Write-Host "Pre-Execution Report"
	Write-Host "`nPowerShell Remoting Targets:"
	Write-Host $PSTargets
	Write-Host "`nSMB/PsExec Remoting Targets:"
	Write-Host $SMBTargets
	Write-Host "`nWMI Remoting Targets:"
	Write-Host $WMITargets
	Write-Host "`nTargets with NO REMOTING Options:"
	Write-Host $NoRemoteTargets
	Write-Host "`n========================================================================`n"
	
	if (($SMBConfirmation -eq "y") -OR ($SMBConfirmation -eq "Y")) {
		Write-Host "You have elected to enable PSRemoting via PsExec."
	} else {
		Write-Host "You have elected NOT to enable PSRemoting via PsExec."		
	}
	if (($WMIConfirmation -eq "y") -OR ($WMIConfirmation -eq "Y")) {
		Write-Host "You have elected to enable PSRemoting via WMI."
	} else {
		Write-Host "You have elected NOT to enable PSRemoting via WMI."		
	}
	$ExecuteConfirmation = Read-Host "`nAre you sure you want to execute? [y/n]"
	
	if (($ExecuteConfirmation -eq "y") -OR ($ExecuteConfirmation -eq "Y")) {
		if (($SMBConfirmation -eq "y") -OR ($SMBConfirmation -eq "Y")) {
			Write-Verbose "Executing PsExec..."
			if ( -Not (Test-Path .\PsExec.exe)) {
				Write-Warning "You must have PsExec.exe in the current working directory to run this function!"
				continue
			}
			# Enable WinRM via PsExec
			$SMBChangedTargets = Enable-WinRMPsExec -SMBTargets $SMBTargets
			
			#Write-Verbose "`n`nValue of SMBChangedTargets: $SMBChangedTargets"
			
			# Determine which systems failed enabling PSRemoting via PsExec and store in variable SMBFailedTargets
			if ($SMBChangedTargets -ne $null) {
				$SMBFailedTargets = Compare-Object -ReferenceObject $SMBChangedTargets -DifferenceObject $SMBTargets -PassThru
			} else {
				$SMBFailedTargets = $SMBTargets
			}
			
			# If PsExec fails on systems and WMI is allowed by user, Attempt enable via WMI
			if (($SMBFailedTargets -ne $null) -AND (($WMIConfirmation -eq "y") -OR ($WMIConfirmation -eq "Y")) ) {
				Write-Verbose "Adding SMB Failed Targets to WMI Targets..."
				$WMITargets += $SMBFailedTargets
			}
		}
		if (($WMIConfirmation -eq "y") -OR ($WMIConfirmation -eq "Y")) {
			Write-Verbose "Executing WMI..."
			$WMIChangedTargets += Enable-WinRMWMI -WMITargets $WMITargets
			
			#Write-Verbose "`n`nValue of WMIChangedTargets: $WMIChangedTargets"
			
			# Determine which systems failed enabling PSRemoting via PsExec and store in variable WMIFailedTargets
			if ($WMIChangedTargets -ne $null) {
				$WMIFailedTargets = Compare-Object -ReferenceObject $WMIChangedTargets -DifferenceObject $WMITargets -PassThru
			} else {
				$WMIFailedTargets = $WMITargets
			}
		}
	} else {
		Write-Verbose "Exiting..."
		continue
	}
	
	Write-Host "`n========================================================================"
	Write-Host "Post-Execution Report"
	Write-Host "`nPowerShell Remoting Targets:"
	Write-Host $PSTargets
	Write-Host "`n`nSMB/PsExec Remoting Targets SUCCESS enabling PSRemoting:"
	Write-Host $SMBChangedTargets
	Write-Host "`nSMB/PsExec Remoting Targets FAILED enabling PSRemoting:"
	Write-Host $SMBFailedTargets
	Write-Host "`n`nWMI Remoting Targets SUCCESS enabling PSRemoting:"
	Write-Host $WMIChangedTargets
	Write-Host "`nWMI Remoting Targets FAILED enabling PSRemoting:"
	Write-Host $WMIFailedTargets
	Write-Host "`n`nTargets with NO REMOTING Options:"
	Write-Host $NoRemoteTargets
	$PSTargets += $SMBChangedTargets
	$PSTargets += $WMIChangedTargets
	Write-Host "`n`nFINAL Targets ready for PSRemoting:"
	Write-Host $PSTargets
	Write-Host "========================================================================`n"
	
	return $PSTargets
}

function Enable-WinRMPsExec {
	[cmdletbinding()]
	Param([String[]] $SMBTargets)
	$ChangedTargets = @()
	
	if ( -Not (Test-Path .\PsExec.exe)) {
		Write-Warning "You must have PsExec.exe in the current working directory to run this function!"
		continue
	}
	
	foreach ($i in $SMBTargets) {
		# Enable WinRM over PsExec
		Write-Verbose "Executing winrm quickconfig -q on $i with PsExec"
		$a = .\PsExec.exe \\$i -s winrm.cmd quickconfig -q 2>&1>$null
		if ( Test-WSMan $i -EA SilentlyContinue ) {
			Write-Verbose "Success enabling PSRemoting on $i with PsExec"
			$ChangedTargets += $i
		} else {
			Write-Warning "PsExec Failed!"
		}
	}
	return $ChangedTargets
}


function Enable-WinRMWMI {
	[cmdletbinding()]
	Param([String[]] $WMITargets)
	$ChangedTargets = @()
	
	foreach ($i in $WMITargets) {
		# Enable WinRM over WMI
		Write-Verbose "Executing winrm quickconfig -q on $i with WMI"
		$a = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "CMD.EXE /c winrm quickconfig -q" -ComputerName $i -EnableAllPrivileges 2>&1>$null
		$a = Start-Sleep 3
		if ( Test-WSMan $i -EA SilentlyContinue ) {
			Write-Verbose "Success enabling PSRemoting on $i with WMI"
			$ChangedTargets += $i
		} else {
			Write-Warning "WMI Failed!"
		}
	}
	return $ChangedTargets
}


function Disable-WinRM {
	[cmdletbinding()]
	Param([String[]] $Targets)
	
	$VerbosePreference = "Continue"
	
	if ( -Not (Test-Path .\PsExec.exe)) {
		Write-Warning "You must have PsExec.exe in the current working directory to run this function!"
		Exit
	}
	
	foreach ($i in $Targets)
	{
		# Disable WinRM over PsExec
		Write-Verbose "Executing winrm delete listener on $i"
		.\PsExec.exe \\$i -s winrm.cmd delete winrm/config/Listener?Address=*+Transport=HTTP
		Write-Verbose "Executing sc stop winrm on $i"
		.\PsExec.exe \\$i -s sc stop winrm
		Write-Verbose "Executing sc config winrm start= disabled on $i"
		.\PsExec.exe \\$i -s sc config winrm start= disabled
	}
}

function Get-BetterTasklist {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r
	$betterPsList = Get-WmiObject -Class Win32_process `
		| select -property Name,ProcessID,ParentProcessId,ExecutablePath,CommandLine `
		| Foreach {
			if ($_.ExecutablePath -ne $null -AND -NOT $NoHash) {
				$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
				$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($_.ExecutablePath)))
				$_ | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
			} else {
				$_ | Add-Member -MemberType NoteProperty Hash $null
			}
			$_ | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
			$_
		}
	$betterPsList | Select TimeGenerated,Name,ProcessID,ParentProcessId,ExecutablePath,Hash,CommandLine
}

function Get-DLLs {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r
	$results = Get-Process | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | sort FileName -Unique | % {
		if ($_.FileName -ne $null -AND -NOT $NoHash) {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($_.FileName)))
			$_ | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
		}
		else {
			$_ | Add-Member -MemberType NoteProperty Hash $null
		}
		$_ | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
		$_
	}
	$results | select TimeGenerated,ModuleName,FileName,Hash,Size,Company,Description,FileVersion,Product,ProductVersion 
}

function Get-BetterNetstatTCP {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r

	# TCP
	$data = netstat -nao -p TCP
	$betterNetstat = Foreach ($line in $data[4..$data.count])
	{
		$line = $line -replace '^\s+',''
		$line = $line -split '\s+'
		$properties = @{
			Protocol = $line[0]
			LocalAddressIP = ($line[1] -split ":")[0]
			LocalAddressPort = ($line[1] -split ":")[1]
			ForeignAddressIP = ($line[2] -split ":")[0]
			ForeignAddressPort = ($line[2] -split ":")[1]
			State = $line[3]
			ProcessId = $line[4]
		}
		$currentLineObj = New-Object -TypeName PSObject -Property $properties
		$proc = get-wmiobject -query ('select * from win32_process where ProcessId="{0}"' -f $line[4])
		$currentLineObj | Add-Member -MemberType NoteProperty ParentProcessId $proc.ParentProcessId
		$currentLineObj | Add-Member -MemberType NoteProperty Name $proc.Caption
		$currentLineObj | Add-Member -MemberType NoteProperty ExecutablePath $proc.ExecutablePath
		if ($currentLineObj.ExecutablePath -ne $null -AND -NOT $NoHash) {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($proc.ExecutablePath)))
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
		}
		else {
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $null
		}
		$currentLineObj | Add-Member -MemberType NoteProperty CommandLine $proc.CommandLine
		$currentLineObj | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
		$currentLineObj
	}
	$betterNetstat | select TimeGenerated,Protocol,LocalAddressIP,LocalAddressPort,ForeignAddressIP,ForeignAddressPort,State,Name,ProcessId,ParentProcessId,ExecutablePath,Hash,CommandLine
}
		
	
function Get-BetterNetstatTCPv6 {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r

	# TCPv6 
	$data = netstat -nao -p TCPv6
	$betterNetstat = Foreach ($line in $data[4..$data.count])
	{
		$line = $line -replace '^\s+',''
		$line = $line -split '\s+'
		$properties = @{
			Protocol = $line[0]
			LocalAddress = $line[1]
			ForeignAddress = $line[2]
			State = $line[3]
			ProcessId = $line[4]
		}
		$currentLineObj = New-Object -TypeName PSObject -Property $properties
		$proc = get-wmiobject -query ('select * from win32_process where ProcessId="{0}"' -f $line[4])
		$currentLineObj | Add-Member -MemberType NoteProperty ParentProcessId $proc.ParentProcessId
		$currentLineObj | Add-Member -MemberType NoteProperty Name $proc.Caption
		$currentLineObj | Add-Member -MemberType NoteProperty ExecutablePath $proc.ExecutablePath
		if ($currentLineObj.ExecutablePath -ne $null -AND -NOT $NoHash) {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($proc.ExecutablePath)))
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
		}
		else {
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $null
		}
		$currentLineObj | Add-Member -MemberType NoteProperty CommandLine $proc.CommandLine
		$currentLineObj | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
		$currentLineObj
	}
	$betterNetstat | select TimeGenerated,Protocol,LocalAddress,ForeignAddress,State,Name,ProcessId,ParentProcessId,ExecutablePath,Hash,CommandLine 
}


function Get-BetterNetstatUDP {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r

	# Now UDP
	$data = netstat -nao -p UDP
	$betterNetstat = Foreach ($line in $data[4..$data.count])
	{
		$line = $line -replace '^\s+',''
		$line = $line -split '\s+'
		$properties = @{
			Protocol = $line[0]
			LocalAddressIP = ($line[1] -split ":")[0]
			LocalAddressPort = ($line[1] -split ":")[1]
			ForeignAddressIP = ($line[2] -split ":")[0]
			ForeignAddressPort = ($line[2] -split ":")[1]
			#State = $line[3]
			ProcessId = $line[3]
		}
		$currentLineObj = New-Object -TypeName PSObject -Property $properties
		$proc = get-wmiobject -query ('select * from win32_process where ProcessId="{0}"' -f $line[3])
		$currentLineObj | Add-Member -MemberType NoteProperty ParentProcessId $proc.ParentProcessId
		$currentLineObj | Add-Member -MemberType NoteProperty Name $proc.Caption
		$currentLineObj | Add-Member -MemberType NoteProperty ExecutablePath $proc.ExecutablePath
		if ($currentLineObj.ExecutablePath -ne $null -AND -NOT $NoHash -AND $proc.Caption -ne "dns.exe") {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($proc.ExecutablePath)))
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
		}
		else {
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $null
		}
		$currentLineObj | Add-Member -MemberType NoteProperty CommandLine $proc.CommandLine
		$currentLineObj | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
		$currentLineObj
	}
	$betterNetstat | select TimeGenerated,Protocol,LocalAddressIP,LocalAddressPort,Name,ProcessId,ParentProcessId,ExecutablePath,Hash,CommandLine
}	

function Get-BetterNetstatUDPv6 {
	[cmdletbinding()]
	Param([bool] $NoHash = $false)
	$TimeGenerated = get-date -format r

	# Now UDPv6
	$data = netstat -nao -p UDPv6
	$betterNetstat = Foreach ($line in $data[4..$data.count])
	{
		$line = $line -replace '^\s+',''
		$line = $line -split '\s+'
		$properties = @{
			Protocol = $line[0]
			LocalAddress = $line[1]
			ForeignAddress = $line[2]
			ProcessId = $line[3]
		}
		$currentLineObj = New-Object -TypeName PSObject -Property $properties
		$proc = get-wmiobject -query ('select * from win32_process where ProcessId="{0}"' -f $line[3])
		$currentLineObj | Add-Member -MemberType NoteProperty ParentProcessId $proc.ParentProcessId
		$currentLineObj | Add-Member -MemberType NoteProperty Name $proc.Caption
		$currentLineObj | Add-Member -MemberType NoteProperty ExecutablePath $proc.ExecutablePath
		if ($currentLineObj.ExecutablePath -ne $null -AND -NOT $NoHash) {
			$sha1 = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
			$hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($proc.ExecutablePath)))
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $($hash -replace "-","")
		}
		else {
			$currentLineObj | Add-Member -MemberType NoteProperty Hash $null
		}
		$currentLineObj | Add-Member -MemberType NoteProperty CommandLine $proc.CommandLine
		$currentLineObj | Add-Member -MemberType NoteProperty TimeGenerated $TimeGenerated
		$currentLineObj
	}
	$betterNetstat | select TimeGenerated,Protocol,LocalAddress,Name,ProcessId,ParentProcessId,ExecutablePath,Hash,CommandLine
}

function Invoke-Autorunsc {
	[cmdletbinding()]
	Param([String] $url)	
	# python -m SimpleHTTPServer 8080
	$urla = $url + "autorunsc.exe"
	$path = "C:\autorunsc.exe"
	(New-Object Net.WebClient).DownloadFile($urla, $path)
	$results = & $path -accepteula -h -c -nobanner -a * -s | ConvertFrom-Csv
	Remove-Item $path
	$results
}


function Invoke-Sigcheck {
	[cmdletbinding()]
	Param([String] $url)	
	
	$verifyHashFunc = 'HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData'
	$PowerShellSIPGuid = '{603BCC1F-4B59-4E08-B724-D2C6297EF351}'
	$PESIDPGuid = '{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'
	
	if ((Get-ItemProperty -Path "$verifyHashFunc\$PowerShellSIPGuid\" -Name "FuncName").FuncName -ne "PsVerifyHash") {
		Write-Error "The System Signature Trust is Subverted!!!"
		Exit
	} elseif ((Get-ItemProperty -Path "$verifyHashFunc\$PowerShellSIPGuid\" -Name "Dll").Dll -ne "C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll") {
		Write-Error "The System Signature Trust is Subverted!!!"
		Exit
	} elseif ((Get-ItemProperty -Path "$verifyHashFunc\$PESIDPGuid\" -Name "FuncName").FuncName -ne "CryptSIPVerifyIndirectData") {
		Write-Error "The System Signature Trust is Subverted!!!"
		Exit
	} elseif ((Get-ItemProperty -Path "$verifyHashFunc\$PESIDPGuid\" -Name "Dll").Dll -ne "C:\Windows\System32\WINTRUST.DLL" -AND (Get-ItemProperty -Path "$verifyHashFunc\$PESIDPGuid\" -Name "Dll").Dll -ne "WINTRUST.DLL") {
		Write-Error "The System Signature Trust is Subverted!!!"
		Exit
	}
	
	$urls = $url + "sigcheck.exe"
	$path = "C:\sigcheck.exe"
	(New-Object Net.WebClient).DownloadFile($urls, $path)
	$results = & $path -accepteula -c -u -e -s -r -nobanner C:\Windows\System32 | ConvertFrom-Csv
	$results += & $path -accepteula -c -u -e -s -r -nobanner C:\Windows\SysWOW64 | ConvertFrom-Csv
	$results
	Remove-Item $path
}


function Get-AuditOptions {
$regConfig = @"
regKey,name
"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa","scenoapplylegacyauditpolicy"
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit","ProcessCreationIncludeCmdLine_Enabled"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","EnableTranscripting"
"HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription","OutputDirectory"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","EnableScriptBlockLogging"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging","EnableModuleLogging"
"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",1
"@


$regConfig | ConvertFrom-Csv | ForEach-Object {
	if (-Not (Test-Path $_.regKey)) {
		# Registry path does not exist -> document DNE
		#Write-Warning "Path $($_.regKey) does not exist"
		New-Object PSObject -Property @{regKey = $_.regKey; name = "DNE"; value = "DNE"}
	}
	else {
		if ((Get-ItemProperty $_.regKey | Select-Object -Property $_.name).$_.name -ne $null) {
			# Registry key exists. Document value
			#Write-Warning "Key $($_.regKey) if $(Get-ItemProperty $_.regKey | Select-Object -Property $_.name)"
			#Write-Warning "Property $($_.name) exists. Documenting Value: $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $_.name)"
			# Handle Cases where SubscriptionManager value already exists.
			if ($_.regKey -like "*SubscriptionManager*") {
				#Write-Warning "RegKey is Like SubscriptionManager"
				#Write-Warning "Property = $($_.name)"
				$wecNum = 1
				# Backup each currently configured SubscriptionManager values.
				while ( (Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $([string]$wecNum) -ErrorAction SilentlyContinue) ) {
					#Write-Warning "RegKey with property = $wecNum exists"
					New-Object PSObject -Property @{regKey = $_.regKey; name = $wecNum; value = $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $([string]$wecNum))}
					#Write-Warning "Incrementing wecNum"
					$wecNum++
				}
			}
			# Backup all non-SubscriptionManager values to array.
			else {
				New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = $(Get-ItemProperty $_.regKey | Select-Object -ExpandProperty $_.name)}
			}
		}
		else {
			# Registry key does not exist. Document DNE
			#Write-Warning "Property $($_.name) DNE. Documenting Null"
			New-Object PSObject -Property @{regKey = $_.regKey; name = $_.name; value = "DNE"}
		}
	}
}

}
