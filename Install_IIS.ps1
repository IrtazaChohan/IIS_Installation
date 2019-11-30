<#

.SYNOPSIS

This script will install and configure IIS on a server (IIS 8.5 and onwards).

Written by Irtaza Chohan (http://www.lostintheclouds.net & https://github.com/IrtazaChohan/Align-Crypto-Policy)

.DESCRIPTION

This script will install and configure IIS on a server (IIS 8.5 and onwards).

This will install various roles and configure IIS using security best practise and replace the default IIS website with a custom one.
The location of the custom IIS page needs to be in the same folder as this script.

Various verbs are configured, request filtering and authentication are also setup accordingly.

This has been tested on:

- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019


NOTES:

1. You need to have Administrative rights on the server to run this script. 
2. If no argument entered it will default to install on D: drive
3. If you want to enter a different drive then enter in the format <DRIVE>: ie E: F: etc - anything else other than a valid drive the script will fail. 
 

.PARAMETER LogFilePath

Mandatory Parameter

Please specify where on the server you want to keep the logfile that is generated.

.PARAMETER Drive

Optional Parameter

Please specify where on the server you want to install and configure IIS. If no drive is specified then this script will install onto the D: drive (so have a D: drive present at least).

.EXAMPLE

This will install IIS on the D: drive and use C:\temp as the installation logging directory.

.\Install_IIS.ps1 -Drive d: -LogFilePath c:\temp


.NOTES

1. You need to have Administrative rights on the server to run this script. 
2. If no argument entered it will default to install on D: drive
3. If you want to enter a different drive then enter in the format <DRIVE>: ie E: F: etc - anything else other than a valid drive the script will fail. 


.LINK

http://www.lostintheclouds.net & https://github.com/IrtazaChohan

#>



param (

[Parameter(Position = 1,
            HelpMessage="Please enter a drive where you want IIS 8.5 to be installed - ie D: or E: - you cannot choose C: drive")] 
            [ValidateCount(1,2)]
            [string]$Drive,
            [Parameter(Mandatory=$True)]
            [string]$LogFilePath

)



function writelog([string]$result, [string]$logfile) {
    try {
        $objlogfile = new-object system.io.streamwriter("$LogFilePath\$logfile", [System.IO.FileMode]::Append)
        $objlogfile.writeline("$((Get-Date).ToString()) : $result")
        write-host (Get-Date).ToString() " : $result"  -foregroundcolor yellow
        $objlogfile.close()
    } catch [Exception] {
        Write-Host $result -foregroundcolor red
        $error.clear()
   }
} 

function rename([string]$oldname,[string]$newname,[string]$oldpath, [string]$olddrive, [string]$newdrive,[string]$newpath){
    Try {
        writelog "Renaming $oldname at this path $olddrive$oldpath to new name of $newname at this path - $newdrive$newpath" $log
        Rename-Item -Path $olddrive$oldpath -NewName $newdrive$newpath -ErrorAction Stop
    }
    catch {
        writelog "ERROR: $Error[0]" $log 
        $Error[0]
        $error.Clear()
        Exit -1
    }

}

$ScriptName = $MyInvocation.MyCommand.Name
$log = "Install_IIS.log"

writelog "================================" $log
writelog "$ScriptName Script Started" $log
writelog "--------------------------------" $log

If($drive -eq ""){

    writelog "No argument was entered - D: drive will now be used" $log
    [string]$drive = "D:"
    writelog "Drive that will be used is $drive" $log
}
else{
    writelog "$drive parameter was entered" $log
        if ($Drive -match "[d-z]:"){
            writelog "Parameter has been entered in correctly" $log
            writelog "Drive to be used will be $drive" $log
           }
        else{
            writelog "Wrong parameter has been detected - you cannot use C: drive; please enter another drive. Ensure the parameter is entered in this format D: E: F: etc" $log
            writelog "Paramter inputted was $drive" $log
            Exit -1
        }
}

Import-Module Servermanager

$CheckDrive = Test-Path -Path $Drive

If ($CheckDrive){
    
    writelog "Installing IIS Features on Server $env:COMPUTERNAME on drive $drive" $log
   
    Add-WindowsFeature Web-Server, Web-WebServer, Web-Security, Web-Filtering, Web-Cert-Auth, Web-IP-Security, Web-Url-Auth, Web-Windows-Auth, 
    Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-CertProvider, Web-Common-Http, Web-Http-Errors, Web-Dir-Browsing, Web-Static-Content,
    Web-Default-Doc, Web-Http-Redirect, Web-DAV-Publishing, Web-Performance, Web-Stat-Compression, Web-Dyn-Compression, Web-Health, Web-Http-Logging,
    Web-ODBC-Logging, Web-Log-Libraries, Web-Custom-Logging, Web-Request-Monitor, Web-Http-Tracing, Web-App-Dev, Web-Net-Ext, Web-Net-Ext45, Web-ASP,
    Web-Asp-Net, Web-Asp-Net45, Web-CGI, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-WebSockets, Web-AppInit, Web-Includes, Web-Mgmt-Tools, Web-Scripting-Tools, Web-Mgmt-Service
      
}
else{s
    writelog "$drive Drive does not exist. You require a valid drive for IIS to be installed - please enter in a valid drive." $log
    Exit -1
}

Import-Module WebAdministration

writelog "Creating New Directory in drive specified" $log
New-Item -Path $drive\inetpub -type Directory -ErrorAction SilentlyContinue

writelog "Copy files from C:\inetpub" $log
Copy-Item -Path C:\inetpub\* -Destination $drive\inetpub\ -Recurse

writelog "Creating new log folder" $log
New-Item -Path $drive\inetpub\logs\logFiles -ItemType Directory

writelog "Creating failedRequests log folder" $log
New-Item -Path $drive\inetpub\logs\FailedRequests -ItemType Directory

rename -oldname 'custerr' -newname 'CustomError' -olddrive $Drive -oldpath '\inetpub\custerr' -newdrive $drive -newpath '\inetpub\CustomError'
rename -oldname 'history' -newname 'ConfigHistory' -olddrive $Drive -oldpath '\inetpub\history' -newdrive $drive -newpath '\inetpub\ConfigHistory'
rename -oldname 'IIS Temporary Compressed Files' -newname 'CompressedFiles' -olddrive $Drive -oldpath '\inetpub\temp\IIS Temporary Compressed Files' -newdrive $drive -newpath '\inetpub\temp\CompressedFiles'

writelog "Changing Root Path Directory" $log
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp' -Name 'PathWWWRoot' -Value "$drive\inetpub" -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp' -Name 'PathWWWRoot' -Value "$drive\inetpub" -Force

writelog "Removing Default WebSite" $log
Remove-Website -Name 'Default Web Site'

Stop-Service -Name W3SVC -Force
Stop-Service -Name WAS -Force

writelog "Reconfiguring default logs directory location" $log
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/log' -Name 'centralW3CLogFile' -Value (@{directory="$drive\inetpub\logs\logFiles"})
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults' -Name 'logFile' -Value (@{directory="$drive\inetpub\logs\logFiles"})
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults' -Name 'traceFailedRequestsLogging' -Value (@{directory="$drive\inetpub\logs\failedRequests"})

writelog "Removing iisstart.htm from default documents list" $log
Remove-WebconfigurationProperty -Filter "system.webServer/defaultDocument/files" "Machine/WebRoot/AppHost" -Name collection -AtElement @{value="iisstart.htm"}

writelog "Removing index.html" $log
Remove-WebconfigurationProperty -Filter "system.webServer/defaultDocument/files" "Machine/WebRoot/AppHost" -Name collection -AtElement @{value="index.html"}

writelog "Now adding index.html back in to top order" $log
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/defaultDocument' -Name "files" -AtIndex 0 -AtElement @{value="index.html"}

writelog "Disabling and removing CentralBinaryLogFile" $log
Set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/log/centralBinaryLogFile' -value @{enabled=$false}
Clear-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/log/centralBinaryLogFile'

writelog "Reconfiguring default configHistory directory location" $log
set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/configHistory' -Value @{path="$drive\inetmgr\configHistory /commit:apphost"}

writelog "Creating registry entry for Application Pool temp directory" $log
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\WAS\Parameters' -Name 'ConfigIsolationPath' -Value "$drive\inetpub\temp\appPools" -Force

writelog "Reconfiguring default logs directory location" $log
Set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/log/centralW3CLogFile' -value @{directory="$drive\inetpub\logs\logFiles"}
Set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/logFile' -value @{directory="$drive\inetpub\logs\logFiles"}

writelog "Reconfiguring default compression directory location" $log
Set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webserver/httpCompression' -value @{directory="$drive\inetpub\temp\CompressedFiles"}

writelog "Creating directory for Custom Default Web Site" $log
New-Item -Path "$drive\inetpub\wwwroot\Custom Default Web Site" -type Directory

Try {
    writelog "Copying down default website index.html" $log
    Copy-Item $PSScriptRoot\index.html -Destination "$drive\inetpub\wwwroot\Custom Default Web Site" -Force

}
catch {
        writelog "ERROR: $Error[0]" $log 
        $Error[0]
        $error.Clear()
        Exit -1

    }

writelog "Creating new website" $log
New-Item "iis:\Sites\Custom Default Web Site" -bindings @{protocol="http";bindingInformation="*:80:"} -physicalPath "$drive\inetpub\wwwroot\Custom Default Web Site"

writelog "Change location of logging directory" $log
Set-ItemProperty 'IIS:\Sites\Custom Default Web Site' -Name logfile.directory "$drive\IIS"

writelog "Disabling anonymous authentication" $log
set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webserver/security/authentication/anonymousAuthentication' -Value @{enabled=$false;userName=""}
Clear-WebConfiguration -Filter "system.webserver/security/authentication/anonymousAuthentication/@password" -PSPath 'MACHINE/WEBROOT/APPHOST'

writelog "Enabling Windows authentication" $log
set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webserver/security/authentication/windowsAuthentication' -Value @{enabled=$true}

writelog "Applying file extension request filters" $log
set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webserver/security/requestFiltering' -Value @{enabled=$true}

writelog "Applying file extension request filters" $log
Add-WebConfigurationProperty -filter "/system.webserver/security/requestFiltering/fileExtensions" -value @{fileExtension=".exe";allowed=$false} -name collection  

writelog "Applying URL sequence request filters" $log
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webserver/security/requestFiltering/denyUrlSequences' -Value @{sequence="\"} -Name collection

writelog "Applying HTTP verb request filters" $log
set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/verbs' -Value @{allowUnlisted=$false}
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name "verbs" -AtElement @{VERB="GET";allowed="True"}
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name "verbs" -AtElement @{VERB="HEAD";allowed="True"}
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name "verbs" -AtElement @{VERB="POST";allowed="True"}

writelog "Reconfiguring default compression directory location" $log
Set-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/asp/cache' -value @{diskTemplateCacheDirectory="$drive\inetpub\temp\ASP Compiled Templates"}

writelog "Granting rights IIS_IUSRS to inetpub directory)" $log
Icacls "$drive\inetpub" /GRANT '"IIS_IUSRS":(OI)(CI)(X,RD,GR,RC,RA) /inheritance:e' /T /C

writelog "Granting rights Network Service to inetpub directory)" $log
Icacls "$drive\inetpub" /GRANT '"NETWORK SERVICE":(OI)(CI)(X,RD,GR,RC,RA) /inheritance:e' /T /C

writelog "Removing iistart.htm file" $log
Remove-Item "$drive\inetpub\wwwroot\iisstart.htm" -Force

writelog "Removing iis-85.png file" $log
Remove-Item "$drive\inetpub\wwwroot\iis-85.png" -Force -ErrorAction SilentlyContinue

writelog "Starting IIS services" $log
invoke-command -scriptblock {iisreset /start}

writelog "Setting WAS to autostart" $log
Set-Service -Name WAS -StartupType Automatic

writelog "$ScriptName Script ended" $log
writelog "==============================" $log