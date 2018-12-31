# Install-Application
Installs an Application from a specified media source by executing the setup installer (.EXE) file along with any install arguments like /S silent switches.
This script could be used with the Windows Server GPO PowerShell Start up Script feature to install a specific application.

## Why do we need this? 
With a need to install an exe (in particular Microsoft’s ATP – Advanced Threat Protection installer) at startup, only if the required version isn’t already installed; I ended up finding a script written by Dan Scott-Raynsford (https://dscottraynsford.wordpress.com/).

It worked OK but wasn’t perfect for our needs due to 2 issues; 1 being the spaces in the installer exe filename and 2 the use of quotes in the arguments needed to be supplied in the install string. The spaces in the filename could easily be resolved by editing the filename but I needed to make the passing in of multiple peculiar arguments more straight-forward anyway so may as well make the script as robust as possible.

I modified Dan's script to allow for these requirements plus some extra features and more verbose logging.

- Changed parameter InstallerParameters to accept a string list.
- Changed method of calling the installer from "cmd.exe /c" to creating a System.Diagnostics.Process and passing in the installer path and parameters separately. This takes care of .exe filenames that may have spaces as well as mulitiple arguments where they must use quote characters.
- Added more verbose logging and output.
- Added parameter to allow checking for a RunOnce registry entry, and skip calling the installer if it exists.

## Usage
It's written as a script which you can run as below

If your install string looks like this...
```
Azure ATP sensor Setup.exe AccessKey="123456123456123456" /quiet NetFrameworkCommandLineArguments="/q"
```
Then you pass in `Azure ATP sensor Setup.exe` as the `-InstallerPath` parameter and each of the 3 arguments as a list to the `-InstallerParameters` parameter
like...    
```
.\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="123456123456123456"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp'
```
 This will then run the `Install Azure ATP sensor Setup.exe` along with the 3 supplied arguments
  - `AccessKey="123456123456123456"`
  - `/quiet`
  - `NetFrameworkCommandLineArguments="/q"`
  and create a log file in "C:\temp"
  
## GPO
As Dan mentions at this blog (https://dscottraynsford.wordpress.com/) there are character length limitations when setting up a Startup script policy. To get around this you can modify the .ps1 script, turning it into a function and calling that function along with the script parameters from within the .ps1 script file, as an example

Before, `Install-Application.ps1` looks like...
```
param (
  $InstallerPath,
  $InstallerParameters,
  $LogPath
)

# perform install etc.
# write log file
```
and you run it as above: `.\Install-Application.ps1 -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="123456123456123456"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp'`

After, Install-Application.ps1 looks like...
```
function Install-App {
  param (
    $InstallerPath,
    $InstallerParameters,
    $LogPath
  )

  # perform install etc.
  # write log file
 }
 Install-App -InstallerPath 'C:\temp\Azure ATP sensor Setup.exe' -InstallerParameters '/quiet','AccessKey="123456123456123456"','NetFrameworkCommandLineArguments="/q"' -LogPath 'C:\temp'
```
So now you can just run the `Install-Application.ps1` script and the Parameters etc are written at the bottom of the script, calling the newly created function `Install-App` (or whatever you decide to call the function; you can always rename to the script too, to be more relevant to the name of the .exe you're passing into the function)

## Registry
Because this script may be run as a Startup policy, Dan (https://dscottraynsford.wordpress.com/) built in a Registry Key and/or Regitry Property check so as not to execute the installer if a particular Registry Key and/or Property value exists...
```
.\Install-Application.ps1 -InstallerPath 'C:\temp\npp.7.6.1.Installer.exe' -InstallerParameters '/S' -RegistryKey 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++' -RegistryName 'DisplayVersion' -RegistryValue '7.6.1' -LogPath 'C:\Temp'
```
This will install Notepad++ 7.6.1 silently ONLY if the registry key value HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++ 'DisplayVersion' does NOT match '7.6.1', creating a log file in C:\Temp folder
*NOTE: -RegistryName and -RegistryValue MUST be passed together*

## RunOnce
Some installers will silently restart halfway through an install based on software dependencies and can add a RunOnce entry to the Registry which allows the installer to carry on with its installation after the restart. Because this script may be added as a Startup policy, I added a `-SkipIfRunOnceSet` switch which will look for **any** RunOnce entries in the Registry, and stop running the script if there are any entries. The particular entries are logged to the log file *if a `-LogPath` is set*
