<#
  .SYNOPSIS
    Installs an Application from a local or network media source

  .DESCRIPTION
    Installs an Application from a specified media source by executing the setup installer (.EXE) file.
    This script would normally be used with the Windows Server 2012 GPO PowerShell Start up Script feature to install a specific application.

  .PARAMETER InstallerPath
    The location of the installation application executable. Can be a local or network path.

  .PARAMETER InstallerParameters
    Optional comma separated list containing any installation parameters that should be passed to the installation executable, usually to force an unattended and silent installation.
    NOTE: use double quotes when wanting a quote inside a parameter of -InstallerParameters

  .PARAMETER LogPath
    Optional parameter specifying where the installation log file should be written to. If not specified, an installation log file will not be written.
    The installation log file will be named with the name of the computer being installed to.

  .PARAMETER RegistryKey
    The registry key to check for. If the registry key does not exist then the application will be installed.

  .PARAMETER RegistryName
    An optional registry value to check for in the registry key. If the registry key does not contain the registry value with this name then the application will be installed.
    MUST be paired with -RegistryValue

  .PARAMETER RegistryValue
    An optional registry value that the registry name in the key must equal. If the registry name value does not match this parameter then the application will be installed.
    MUST be paired with -RegistryName

  .PARAMETER SkipIfRunOnceSet
    An optional switch which if set/passed in will check for any RunOnce entries in the registry, and if any exist will then skip running the rest of the script as we may be
    in the middle of a current install that required a restart and is continuing the complete the original install.

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "\\server\Software$\Notepad++\npp.6.7.8.2.Installer.exe" -InstallerParameters "/S"

    Description:
    Install Notepad++ 6.7.8.2 without creating a logfile

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "C:\temp\npp.6.7.8.2.Installer.exe" -InstallerParameters "/S" -LogPath "\\Server\Software$\logfiles"

    Description:
    Install Notepad++ 6.7.8.2 creating log files for each machine it is installed on in \\Server\Software$\logfiles\ folder"

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "C:\temp\npp.7.6.1.Installer.exe" -InstallerParameters "/S" -LogPath "C:\Temp" -RegistryKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++" -RegistryName 'DisplayVersion' -RegistryValue '7.6.1'

    Description:
    Install Notepad++ 7.6.1 ONLY if the registry key HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++ does NOT exist AND the RegistryName 'DisplayVersion' with RegistryValue '7.6.1' does NOT match, creating a log file in C:\Temp folder"
    NOTE: -RegistryName and -RegistryValue MUST be passed together, if only one or the other is used, then the script will skip and only check if the -RegistryKey exists alone

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath "C:\temp\npp.7.6.1.Installer.exe" -InstallerParameters "/S" -LogPath "C:\Temp" -RegistryKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++"

    Description:
    Install Notepad++ 7.6.1 ONLY if the registry key HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++ does NOT exist, creating a log file in C:\Temp folder"

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="15678644156731215348691"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp'
    .\Install-Application.ps1 -InstallerPath "C:\temp\Azure ATP sensor Setup.exe" -InstallerParameters "/quiet","AccessKey=""15678644156731215348691""","NetFrameworkCommandLineArguments=""/q""" -LogPath "C:\temp"

    Description:
    Azure ATP sensor Setup.exe AccessKey="15678644156731215348691" /quiet NetFrameworkCommandLineArguments="/q"
    Install Azure ATP sensor Setup.exe creating log files in "C:\temp" folder"
    NOTE: use double quotes to escape a quote when wanting a quote inside a parameter of -InstallerParameters that is inside quotes
          OR, use apostrophes around each param and quotes inside the apostrophes

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="15678644156731215348691"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp' -SkipIfRunOnceSet

    Description:
    Azure ATP sensor Setup.exe AccessKey="15678644156731215348691" /quiet NetFrameworkCommandLineArguments="/q"
    Install Azure ATP sensor Setup.exe creating log files in "C:\temp" folder"
    Skip calling the .exe if a RunOnce registry entry exists (which may do as the installer will install .Net first if it doesn't exist
    which forces a restart before continuine the ATP portion of the install so we don't want to call the .exe again. The ATP installer is
    a WiX based installer which uses the RunOnce key to make continuous installs after required restarts).

  .EXAMPLE
    .\Install-Application.ps1 -InstallerPath 'C:\Windows\System32\msiexec.exe' -InstallerParameters '/i "C:\temp\name of msi installer.msi"','/quiet','/l*v "C:\temp\name of msi installer_msilog.log"' -LogPath 'C:\temp'

    Description:
    For silently installing an msi file
    The path to the installer is actually the exe 'msiexec.exe' and the msi paramters can be then set in the -InstallParameters
    The msi installer's verbose log will be written to C:\temp\name of msi installer_msilog.log
    This script's log will be written to C:\temp

  .NOTES
    Author: Stephen Geall - Output Systems
    Date: December 2018
    Version: 1.1

    Changes: 17/12/2018 v1.0 - Changed parameter InstallerParameters to accept a string list
                        v1.0 - Changed method of calling the installer from "cmd.exe /c" to creating a System.Diagnostics.Process and passing in the installer path
                               and parameters separately making for a more robust script and allowing use a multiple parameters oh which some may contain quotes AND
                               where installer .exe files may contain spaces in their filename.
                        v1.0 - Added more verbose logging and output
             28/12/1028 v1.1 - Added parameter to allow checking for a RunOnce registry entry, and skip calling the installer if it exists

    Modified based on the original script written by
    ::Daniel Scott-Raynsford
    ::http://dscottraynsford.wordpress.com/
    ::VERSION 1.0 2015-06-30  Daniel Scott-Raynsford Incomplete Version
#>


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
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    $RegistryName='',

    [String]
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    $RegistryValue='',

    [Switch]
    [Parameter()]
    $SkipIfRunOnceSet=$False
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
} else {
	[String]$LogFile = Join-Path -Path $LogPath -ChildPath "$($ENV:computername)_$([System.IO.Path]::GetFileNameWithoutExtension($InstallerPath)).txt"
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
        $runOnceList
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
                # Can a Registry Key Property with the name RegistryName be found? If no, then an error will be thrown and
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
                # Registry Key Property not found so not installed.
                Add-LogEntry -Path $LogFile -Message "Registry Item Property $RegistryName was not found, so app is not installed."
            }
        } Else {
            # Only Registry Key was provided for check so app is installed.
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
        1641 { Add-LogEntry -Path $LogFile -Message "Install using [$Command] completed successfully and computer is rebooting (exit code: $ExitCode)." }
        1603 { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode. Does user have permission?" }
        default { Add-LogEntry -Path $LogFile -Message "FAILED? Install using [$Command] ended with exit code $ExitCode." }
    }
} Else {
    Add-LogEntry -Path $LogFile -Message "Application is already installed (based on Registry check)."
}
Add-LogEntry -Path $LogFile -Message "END INSTALL-APPLICATION LOG."
