<#
  .SYNOPSIS
    Installs an Application from a local or network media source

  .DESCRIPTION
    Installs an Application from a specified media source by executing the setup installer (.EXE) file
    along with any Install arguments like /S silent switches.
    This script could be used with the Windows Server GPO PowerShell Start up Script feature to install
    a specific application.

  .PARAMETER InstallerPath
    The location of the installation application executable. Can be a local or network path.

  .PARAMETER InstallerParameters
    Optional comma separated list containing any installation parameters that should be passed to the
    installation executable, usually to force an unattended and silent installation.
    NOTE: either use single and double quotes or 2 double quotes when wanting a quote inside a parameter
    of -InstallerParameters

  .PARAMETER LogPath
    Optional parameter specifying where the installation log file should be written to. If not specified,
    an installation log file will not be written.
    The installation log file will be named with the name of the computer being installed to.

  .PARAMETER RegistryKey
    A registry key to check for. If the registry key does not exist then the application will be installed.

  .PARAMETER RegistryName
    An optional registry value to check for in the registry key. If the registry key does not contain the
    registry value with this name then the application will be installed.
    NOTE: MUST be paired with -RegistryValue

  .PARAMETER RegistryValue
    An optional registry value that the registry name in the key must equal. If the registry name value
    does not match this parameter then the application will be installed.
    NOTE: MUST be paired with -RegistryName

  .PARAMETER SkipIfRunOnceSet
    An optional switch which if set/passed in will check for any RunOnce entries in the registry, and if
    any exist will then skip running the rest of the script as we may be in the middle of a current
    install that required a restart and is continuing the complete the original install.

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "\\server\Software$\Notepad++\npp.6.7.8.2.Installer.exe" -InstallerParameters "/S"

    Description:
    Install Notepad++ 6.7.8.2 silently

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "C:\temp\npp.6.7.8.2.Installer.exe" -InstallerParameters "/S" -LogPath "\\Server\Software$\logfiles"

    Description:
    Install Notepad++ 6.7.8.2 silently creating log files for each machine it is installed on in \\Server\Software$\logfiles\ folder"

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\temp\npp.7.6.1.Installer.exe' -InstallerParameters '/S' -RegistryKey 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++' -RegistryName 'DisplayVersion' -RegistryValue '7.6.1' -LogPath 'C:\Temp'

    Description:
    Install Notepad++ 7.6.1 silently ONLY if the registry key value HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++ 'DisplayVersion' does NOT match '7.6.1', creating a log file in C:\Temp folder
    NOTE: -RegistryName and -RegistryValue MUST be passed together

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "C:\temp\npp.7.6.1.Installer.exe" -InstallerParameters "/S" -RegistryKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++" -LogPath "C:\Temp"

    Description:
    Install Notepad++ 7.6.1 silently ONLY if the registry key HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++ does NOT exist, creating a log file in C:\Temp folder"

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="123456123456123456"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp'
    .\Install-Application.ps1 -InstallerPath "C:\temp\Azure ATP sensor Setup.exe" -InstallerParameters "/quiet","AccessKey=""123456123456123456""","NetFrameworkCommandLineArguments=""/q""" -LogPath "C:\temp"

    Description:
    (both lines will work, just showing the different syntax if using only double["] quotes or if using a mix of single['] and double["])
    Azure ATP sensor Setup.exe AccessKey="123456123456123456" /quiet NetFrameworkCommandLineArguments="/q"
    Install Azure ATP sensor Setup.exe creating log files in "C:\temp" folder"
    NOTE: use double quotes to escape a quote when wanting a quote inside a parameter of -InstallerParameters
          that is inside quotes OR, use apostrophes around each param and quotes inside the apostrophes

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="123456123456123456"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp' -SkipIfRunOnceSet

    Description:
    Azure ATP sensor Setup.exe AccessKey="123456123456123456" /quiet NetFrameworkCommandLineArguments="/q"
    Install Azure ATP sensor Setup.exe creating log files in "C:\temp" folder
    Skip calling the .exe if a RunOnce registry entry exists (which may do as the installer will install .Net
    first if it doesn't exist which forces a restart before continuine the ATP portion of the install so we
    don't want to call the .exe again. The ATP installer is a WiX based installer which uses the RunOnce key
    to make continuous installs after required restarts).

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\Windows\System32\msiexec.exe' -InstallerParameters '/i "C:\temp\name of msi installer.msi"','/quiet','/l*v "C:\temp\name of msi installer_msilog.log"' -LogPath 'C:\temp'

    Description:
    For silently installing an msi file
    The path to the installer is actually the exe 'msiexec.exe' and the msi paramters can be then set in the -InstallParameters
    The msi installer's verbose log will be written to C:\temp\name of msi installer_msilog.log
    This script's log will be written to C:\temp

  .NOTES
    Author: Steve Geall
    Date: December 2018
    Version: 1.2

    Changes: 17/12/2018 v1.1 - Changed parameter InstallerParameters to accept a string list.
                        v1.1 - Changed method of calling the installer from "cmd.exe /c" to creating a
                               System.Diagnostics.Process and passing in the installer path and parameters
                               separately making for a more robust script and allowing use a multiple
                               parameters of which some may contain quotes AND where installer .exe files
                               may contain spaces in their filename/path.
                        v1.1 - Added more verbose logging and output.
             28/12/2018 v1.2 - Added parameter to allow checking for a RunOnce registry entry, and skip
                               calling the installer if it exists.
             23/01/2019 v1.2 - Added regex to handle using the .msi filename for the log filename if installing
                               an msi.
                        v1.2 - Added exit code reasons.

    Modified based on the original script written by
    ::Daniel Scott-Raynsford
    ::http://dscottraynsford.wordpress.com/
    ::VERSION 1.0 2015-06-30  Daniel Scott-Raynsford Incomplete Version
#>
[CmdletBinding(DefaultParametersetName='None')]
param(
    [String]
    [Parameter(Position=1,Mandatory=$true)]
    [ValidateScript( {($_ -ne '') -And (Test-Path $_)} )]
    $InstallerPath,

    [String[]]
    [Parameter()]
    $InstallerParameters='',

    [String]
    [Parameter()]
    [ValidateScript( {($_ -ne '') -And (Test-Path $_)} )]
    $LogPath,

    [String]
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    $RegistryKey='',

    [String]
    [Parameter(ParameterSetName='RegExtra',Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    $RegistryName='',

    [String]
    [Parameter(ParameterSetName='RegExtra',Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    $RegistryValue='',

    [Switch]
    [Parameter()]
    $SkipIfRunOnceSet
)

Function Add-LogEntry ([String]$Path,[String]$Message) {
    Write-Output $Message
    # Only write log entry if a path was specified
    If ( $Path -ne '' ) {
        Add-Content -Path $Path -Value "$(Get-Date): $Message"
    }
}

# If LogPath was specified set up a log filename to write to
If (($LogPath -eq '') -or ($LogPath -eq $null)) {
    [String]$LogFile = ''
} Else {
    $appNameForLogFile = $([System.IO.Path]::GetFileNameWithoutExtension($InstallerPath))
    If ($InstallerPath -like "*msiexec.exe") {
        $InstallerParameters | ForEach-Object {
            # param for msi will be like: '/i "C:\temp\name of msi installer.msi"'
            If ($_ -like "/i*") {
                # regex
                # ^ Begins matching from start of string.
                # .*\\ Matches all the characters upto the last \ symbol.
                # ([^.]*) Captures any character but not . zero or more times.
                # ..* Matches all the remaining characters.
                # use -Match to create the $Matches variable where the desired result will be in $Matches[1]
                $pattern = '^.*\\([^.]*)..*$'
                If ($_ -Match $pattern) {
                    # found msi /i installer file so update $appNameForLogFile to that rather than using $InstallerPath without extension
                    $appNameForLogFile = $Matches[1]
                }
            }
        }
    }
    [String]$LogFile = Join-Path -Path $LogPath -ChildPath "$($ENV:computername)_$appNameForLogFile.txt"
}

Add-LogEntry -Path $LogFile -Message "--------------------------------"
Add-LogEntry -Path $LogFile -Message "BEGIN INSTALL-APPLICATION LOG..."

# Check if -SkipIfRunOnceSet switch parameter passed in
If ($SkipIfRunOnceSet) {
    Write-Host "-SkipIfRunOnceSet switch passed in" -f Yellow
    $runOnceList = @{}
    $RegistryRunOnceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    Push-Location
    Set-Location $RegistryRunOnceKey
    Get-Item . | Select-Object -ExpandProperty Property |
    ForEach-Object {
        $runOnceStringName = $_
        $runOnceStringData = (Get-ItemProperty -Path . -Name $_).$_
        $runOnceList.$runOnceStringName = $runOnceStringData
    }
    Pop-Location
    # If there are RunOnce registry entries, exit this instance of the script
    If ($runOnceList.Count -gt 0) {
        Add-LogEntry -Path $LogFile -Message "Switch parameter -SkipIfRunOnceSet passed in, and there are RunOnce registry entries at they key [$RegistryRunOnceKey], as follows..."
        $runOnceList.GetEnumerator() | ForEach-Object {Add-LogEntry -Path $LogFile -Message " - $($_.Name) [$($_.Value)]"}
        Add-LogEntry -Path $LogFile -Message "Will now exit this script as to not attempt to run the original installer again."
        Add-LogEntry -Path $LogFile -Message "END INSTALL-APPLICATION LOG."
        Exit
    } Else {
        Add-LogEntry -Path $LogFile -Message "There are no RunOnce registry entries, continue with this script..."
    }
}

# Perform registry checks to see if app is already installed
[Boolean]$Installed = $False
If ($RegistryKey) {
    If (Test-Path -Path $RegistryKey) {
        Add-LogEntry -Path $LogFile -Message "Registry Key $RegistryKey found."
        If (($RegistryName -ne $null) -And ($RegistryName -ne '') -And ($RegistryValue -ne $null) -And ($RegistryValue -ne '')) {
            # RegistryName and RegistryValue also passed in for check
            Try {
                # Can a Registry Key Property with the name RegistryName be found? If no, then an error will be thrown
                $RegProperty = Get-ItemProperty -Path $RegistryKey -Name $RegistryName
                Add-LogEntry -Path $LogFile -Message "Registry Item Property $RegistryName found with value $($RegProperty.$RegistryName)."
                # Does the Registry Key Property Value match registry Value?
                If ($RegProperty.$RegistryName -eq $RegistryValue) {
                    # Yes, app is installed.
                    Add-LogEntry -Path $LogFile -Message "Registry Item Property $RegistryName`'s value ($($RegProperty.$RegistryName)) matches passed in -RegistryValue ($RegistryValue), so app is installed."
                    [Boolean]$Installed = $True
                } Else {
                    Add-LogEntry -Path $LogFile -Message "Registry Item Property $RegistryName`'s value ($($RegProperty.$RegistryName)) does not match passed in -RegistryValue ($RegistryValue), so app is not installed."
                }
            } Catch {
                # -RegistryKey property not found so not installed.
                Add-LogEntry -Path $LogFile -Message "Registry Item Property $RegistryName was not found, so app is not installed."
            }
        } Else {
            # Only -RegistryKey was provided for check so app is installed.
            Add-LogEntry -Path $LogFile -Message "RegistryKey was found, but parameters -RegistryName and -RegistryValue were not provided, no more reg to check, assume app is installed."
            [Boolean]$Installed = $True
        }
    } Else {
        Add-LogEntry -Path $LogFile -Message "Registry Key [$RegistryKey] can't be found using Test-Path, `$Installed=$Installed, continue with install... (debug: ensure in the correct format, like 'HKLM:\SOFTWARE\...')"
    }
}

If (!$Installed) {
    [String]$Command="$InstallerPath $InstallerParameters"
    Add-LogEntry -Path $LogFile -Message "Install Application using [$Command] started."
    If ($LogFile) {
        Write-Output "Log will be written to: $LogFile"
    }

    # Call the product install, passing parameters (if any), waiting for the installer to complete and capturing the stdout/err and exitcode
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $InstallerPath
    $pinfo.Arguments = $InstallerParameters
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()

    $ExitCode = $p.ExitCode
    $StdOut = $p.StandardOutput.ReadToEnd();
    $StdErr = $p.StandardError.ReadToEnd();

    If ($ExitCode) {Add-LogEntry -Path $LogFile -Message "  exitcode: $ExitCode"}
    If ($StdOut) {Add-LogEntry -Path $LogFile -Message "  stdout: $StdOut"}
    If ($StdErr) {Add-LogEntry -Path $LogFile -Message "  stderr: $StdErr"}

    Switch ($ExitCode) {
        0 { Add-LogEntry -Path $LogFile -Message "Install using [$Command] completed successfully (exit code: $ExitCode)." }
        1601 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The Windows Installer Service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.." }
        1602 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. User cancelled installation." }
        1603 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Fatal error during installation. Does user have permission?" }
        1604 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Installation suspended, incomplete." }
        1605 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This action is only valid for products that are currently installed." }
        1606 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Feature ID not registered." }
        1607 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Component ID not registered." }
        1608 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Unknown property." }
        1609 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Handle is in an invalid state." }
        1610 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The configuration data for this product is corrupt. Contact your support personnel." }
        1611 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Component qualifier not present." }
        1612 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The installation source for this product is not available. Verify that the source exists and that you can access it." }
        1613 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service." }
        1614 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Product is uninstalled." }
        1615 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. SQL query syntax invalid or unsupported." }
        1616 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Record field does not exist." }
        1617 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The device has been removed." }
        1618 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Another installation is already in progress. Complete that installation before proceeding with this install." }
        1619 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package." }
        1620 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package." }
        1621 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. There was an error starting the Windows Installer service user interface. Contact your support personnel." }
        1622 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Error opening installation log file. Verify that the specified log file location exists and that you can write to it." }
        1623 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The language of this installation package is not supported by your system." }
        1624 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Error applying transforms. Verify that the specified transform paths are valid." }
        1625 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This installation is forbidden by system policy. Contact your system administrator." }
        1626 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Function could not be executed." }
        1627 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Function failed during execution." }
        1628 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Invalid or unknown table specified." }
        1629 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Data supplied is of wrong type." }
        1630 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Data of this type is not supported." }
        1631 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The Windows Installer service failed to start. Contact your support personnel." }
        1632 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder." }
        1633 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This installation package is not supported by this processor type. Contact your product vendor." }
        1634 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Component not used on this computer." }
        1635 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This update package could not be opened. Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package." }
        1636 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This update package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer update package." }
        1637 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. This update package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service." }
        1638 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel." }
        1639 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Invalid command line argument. Consult the Windows Installer SDK for detailed command line help." }
        1640 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Only administrators have permission to add, remove, or configure server software during a Terminal services remote session. If you want to install or configure software on the server, contact your network administrator." }
        1641 { Add-LogEntry -Path $LogFile -Message "Install using [$Command] ended with exit code $ExitCode. The requested operation completed successfully. The system will be restarted so the changes can take effect." }
        1642 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade." }
        1643 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The update package is not permitted by software restriction policy." }
        1644 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. One or more customizations are not permitted by software restriction policy." }
        1645 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The Windows Installer does not permit installation from a Remote Desktop Connection." }
        1646 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Uninstallation of the update package is not supported." }
        1647 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The update is not applied to this product." }
        1648 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. No valid sequence could be found for the set of updates." }
        1649 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Update removal was disallowed by policy." }
        1650 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The XML update data is invalid." }
        1651 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Windows Installer does not permit updating of managed advertised products. At least one feature of the product must be installed before applying the update." }
        1652 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The Windows Installer service is not accessible in Safe Mode. Please try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state." }
        1653 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately." }
        1654 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. The app that you are trying to run is not supported on this version of Windows." }
        default { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode." }
    }
} Else {
    Add-LogEntry -Path $LogFile -Message "Application is already installed (based on Registry check)."
}
Add-LogEntry -Path $LogFile -Message "END INSTALL-APPLICATION LOG."
