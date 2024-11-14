########################################################################
# Detection Script for TeamViewer Device Name Check
# Created by Matt Lavine [@mattlavine](https://github.com/mattlavine)
# Version 1: Update TeamViewer Device Name to match Local Computer Name.
########################################################################
# Purpose of Scripts:
    # The purpose of these Detection and Remediation scripts is to update a device's name in TeamViewer to the following naming scheme: "<COMPUTERNAME>".
    # <COMPUTERNAME> refers to the device's local computer name.
########################################################################
# Requirements

# This is designed and tested to work under the following conditions:
    # Executed by the local system using Intune (or for debugging purposes, run using admin permissions)
    # Running on Windows 10 or 11 64-bit. (The script might function normally if run in Windows 10 or 11 32-bit but in those cases the log messages about TeamViewer 64-bit being installed will be incorrect.)
    # Runs using the PowerShell version built-in to Windows 10/11 - PowerShell v5.1.
    # TeamViewer v15.53 or newer (either Host or Full version) is used, or at least a version that supports using the the new management style: 'DeviceManagementV2' (as it is referred to in the registry). In the TeamViewer Settings GUI, this management style is the "Manage this device" section. The old management style is the "Account assignment" section.
    
# Intune Configuration Settings
    # Run this script using the logged-on credentials = No
    # Enforce script signature check                  = No
    # Run script in 64-bit PowerShell                 = Yes
    
########################################################################
# Info to Run

# Get your TeamViewer Script API token with Device Groups > "read operations" and "modifying operations" permissions: https://www.teamviewer.com/en-us/for-developers/#create-script-section
# As of 7/16/2024, the Device Groups permissions can only be given if creating the script token in the Classic management console (login.teamviewer.com). They do not show up in the new management console (web.teamviewer.com) due to a bug.
# In order to update the name of a device in TeamViewer the account that generates the API token needs to have the "DeviceAdministration" permission to the device either by assigning the manager to the Managed group with that permission (but this method only works on devices that get managed after the new manager is added to the group, existing devices do not get the new manager automatically added to their per-device permissions) or via assigning the permission to the manager on a per-device basis.

# PLEASE NOTE: the reason I set a lot of the variables to $null before using them is to prevent Windows PowerShell ISE from reusing variable values from a previous script run (I know I should use a different app for developing on Windows).

########################################################################
# Helpful Documentation

# Intune Documentation
    # Remediations
        # https://learn.microsoft.com/en-us/mem/intune/fundamentals/remediations
        
# TeamViewer API Documentation
    # Full API Documentation
        # https://webapi.teamviewer.com/api/v1/docs/index#/
    # GET Managed Device
        # https://webapi.teamviewer.com/api/v1/docs/index#!/Managed32Groups/ManagedDevices_Get
    # PUT Managed Device
        # https://webapi.teamviewer.com/api/v1/docs/index#!/Managed32Groups/ManagedDevices_Put
    
# Get the local computer name
    # https://adamtheautomator.com/powershell-to-get-computer-name/
    
# PowerShell Documentation
    # Invoke-WebRequest
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1
    # Invoke-RestMethod
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-5.1
        
# Capturing error information from WebRequest/RestMethod error in PowerShell 5.1 (mainly for Microsoft Graph)
    # https://stackoverflow.com/questions/18771424/how-to-get-powershell-invoke-restmethod-to-return-body-of-http-500-code-response
    
########################################################################
# VARIABLES TO MODIFY

#Enter your TeamViewer Script API token here:
#This token was created by []. This API token only needs the "Device Groups" permissions of "read operations" and "modifying operations".
$ApiToken = ""

$bearer = "Bearer",$ApiToken
$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$header.Add("authorization", $bearer)
$TVURL = "https://webapi.teamviewer.com/api/v1/managed/devices/"

$TV64Bit = 'HKLM:\SOFTWARE\TeamViewer\DeviceManagementV2'
$TV32Bit = 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer\DeviceManagementV2'

$TeamViewerManagementID = $null

#Customize the next line if you want to use something other than the hostname to name your Windows device.
#More info here: https://adamtheautomator.com/powershell-to-get-computer-name/
$ComputerName = ([System.Net.Dns]::GethostName()).ToUpper()

#Customize your log path here
$logPath = "C:\Temp"
if (!(test-path $logPath)) { New-Item -ItemType Directory -Force -Path $logPath }
$logPath += "\TV_Name_Detection_v1.log"

########################################################################

Start-Transcript -Path $logPath -Force -ErrorAction SilentlyContinue

try{
    $TeamViewerManagementID=Get-Item -Path $TV64Bit -ErrorAction Stop #Get TeamViewer ID from the registry for a Full Client install
    $TeamViewerManagementID=(Get-ItemPropertyValue -Path $TV64Bit -Name 'ManagementId') -replace '[{}]'
    Write-Host "TeamViewer 64-bit Client installed"
    Write-Host "Management ID: [$TeamViewerManagementID]"
} catch {
    try {
        $TeamViewerManagementID=Get-Item -Path $TV32Bit -ErrorAction Stop #Get TeamViewer ID from the registry for a Host Client install
        $TeamViewerManagementID=(Get-ItemPropertyValue -Path $TV32Bit -Name 'ManagementId') -replace '[{}]'
        Write-Host "TeamViewer 32-bit Client installed"
        Write-Host "Management ID: [$TeamViewerManagementID]"
    } catch {
        Write-Host "TeamViewer Management ID Not Found in Registry"
        $TeamViewerManagementID = $null
    }
}

if ($null -ne $TeamViewerManagementID) {
    $TVURL += "$TeamViewerManagementID"
    Write-Host "API Request URL: [$TVURL]"
    #Get the device in TeamViewer API by the device's ManagementId using the managed devices endpoint
    $response = Invoke-WebRequest -Uri $TVURL -UseBasicParsing -Headers $header
    if ($response.StatusCode -eq 200) {
        $TVDeviceInfo = $response.Content | ConvertFrom-Json
        $TVDeviceName = $TVDeviceInfo.name
        if ($TVDeviceName -eq $ComputerName) { #Check if names match
            Write-Host "Device name is up-to-date. No action is needed."
            Write-Host "Device Info: [$TVDeviceInfo]"
            Write-Host "TeamViewer Device Name: [$TVDeviceName]"
            Write-Host "Computer Name: [$ComputerName]"
        } else {
            Write-Host "Device name is out of date. Action is needed."
            Write-Host "Device Info: [$TVDeviceInfo]"
            Write-Host "TeamViewer Device Name: [$TVDeviceName]"
            Write-Host "Computer Name: [$ComputerName]"
            Stop-Transcript -ErrorAction SilentlyContinue
            Exit 1
        }
    } elseif ($response.StatusCode -eq 404) {
        Write-Host "Device not found in TeamViewer."
        $TVDeviceError = $response.Content | ConvertFrom-Json
        Write-Host "Error Response: [$TVDeviceError]"
    } else {
        Write-Host "Error finding device in TeamViewer."
        $TVDeviceError = $response.Content | ConvertFrom-Json
        Write-Host "Error Response: [$TVDeviceError]"
    }
}
Stop-Transcript -ErrorAction SilentlyContinue
Exit 0