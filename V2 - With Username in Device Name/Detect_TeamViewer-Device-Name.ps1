########################################################################
# Detection Script for TeamViewer Device Name Check
# Created by Matt Lavine [@mattlavine](https://github.com/mattlavine)
# Version 2: This time it also appends a username to the TeamViewer Device Name.
########################################################################
# Purpose of Scripts:
    # The purpose of these Detection and Remediation scripts is to update a device's name in TeamViewer to the following naming scheme: "<COMPUTERNAME>-<PRIMARYUSER>".
    # <COMPUTERNAME> refers to the device's local computer name
    # <PRIMARYUSER> refers to one of the following:
        # The username portion of the primary user (the part before the [@] with the special characters ['] and [-] removed) as listed in the device's Intune record. In the Intune GUI, this is referred to as the "Primary User". In Microsoft Graph API, this same data point is referred to as the "userPrincipalName".
        # The static text of "UNASSIGNED". If there is no "Primary User" or "userPrincipalName" set for the device record in Intune, then the static text of "UNASSIGNED" is used in place of a username.
    # Examples:
        # [COMPUTERNAME]-mattlavine
        # [COMPUTERNAME]-UNASSIGNED
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

# Microsoft Graph Documentation
    # Get access without a user - Token Generation
        # https://learn.microsoft.com/en-us/graph/auth-v2-service?tabs=http
    # Get managedDevice
        # https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0

# How to get the Intune Device ID from the registry
    # https://www.modernendpoint.com/managed/Dynamically-Update-Primary-Users-on-Intune-Managed-Devices/

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

# Enter your TeamViewer Script API token here:
# This token was created by []. 
# This API token only needs the "Device Groups" permissions of "read operations" and "modifying operations".
$tvAPIToken = ""

# Enter your Entra Registered App info below:
# The app for this script only needs the "DeviceManagementManagedDevices.Read.All" permission.
# Entra App is called [].
# This secret expires on [].
$tenantId = ""
$clientId = ""
$clientSecret = ""

# Customize your log path folder here. Do NOT end the path with a '\'
$logFolderPath = "C:\Temp"

# Change this variable to reflect how you want the log file to be named. Also, make sure to NOT use any spaces in the file name.
$logFileName = "TeamViewer_Device_Name_Detection_v2.log"

########################################################################
# Functions

# This function is for handling errors with the different APIs and returning useful error information. I needed this mainly because the structure of the errors that Microsoft Graph returns are not the same as other APIs.
function Handle-APIRequestError {
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$Error
    )
    
    $statusCode = $null
    $statusDescription = $null
    $errorDetailsMessage = $null
    $responseStream = $null
    $detailedErrorMessage = $null
    
    # Extract and display basic error information
    $statusCode = $Error.Exception.Response.StatusCode.value__
    $statusDescription = $Error.Exception.Response.StatusDescription
    
    Write-Host "[DEBUG] Status Code: " $Error.Exception.Response.StatusCode.value__
    Write-Host "[DEBUG] Status Description: " $Error.Exception.Response.StatusDescription
    
    # Check and display error details
    if ($Error.ErrorDetails) {
        Write-Host "[DEBUG] Error Details key is NOT empty."
        $errorDetailsMessage = $Error.ErrorDetails | ConvertFrom-Json | ConvertTo-Json
    } else {
        Write-Host "[DEBUG] Error Details key is empty."
    }
    
    # Attempt to read and display detailed error message
    try {
        $responseStream = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
        $responseStream.BaseStream.Position = 0
        $responseStream.DiscardBufferedData()
        $detailedErrorMessage = $responseStream.ReadToEnd() | ConvertFrom-Json | ConvertTo-Json
        
        Write-Host "[DEBUG] Detailed Error Response Message:"
        Write-Host $([System.Text.RegularExpressions.Regex]::Unescape($detailedErrorMessage))
        
    } catch {
        if ($errorDetailsMessage) {
            Write-Host "[DEBUG] Simple Error Response Message:"
            Write-Host $([System.Text.RegularExpressions.Regex]::Unescape($errorDetailsMessage))
        } else {
            Write-Host "[ERROR] Error details not available."
        }
    }
}

########################################################################

# Check if the logPath directory exists and create it if it doesn't
if (!(Test-Path $logFolderPath)) {
    New-Item -ItemType Directory -Force -Path $logFolderPath
}
#$datetime   = Get-Date -f 'yyyy-MM-dd-HHmmss'
#$logPath += "\$logFileName-${datetime}.log"

#$logPath += "\$logFileName.log"

$fullLogPath = Join-Path -Path $logFolderPath -ChildPath $logFileName

# Start logging the script here
Start-Transcript -Path $fullLogPath -Force -ErrorAction SilentlyContinue

########################################################################

#Get PowerShell Version
#Write-Host "PowerShell Version Used: " $PSVersionTable.PSVersion.ToString()

$ComputerName = $null

# Customize the next line if you want to use something other than the hostname to name your Windows device.
# More info here: https://adamtheautomator.com/powershell-to-get-computer-name/
#$ComputerName = ([System.Net.Dns]::GetHostName()).ToUpper()
$ComputerName = ($env:COMPUTERNAME).ToUpper()

Write-Host ""
Write-Host "[Part 1] Checking TeamViewer installation and management status..."

# POSSIBLE TO-DO: Might be valuable to add a check to see if the TeamViewer.exe exists in Program Files first before checking the registry

$tvRegSearchPath = $null
#$tvArchitectureVersionInstalled = $null

# Initialize the TeamViewer Management ID
$TeamViewerManagementID = $null

$TV64Bit = 'HKLM:\SOFTWARE\TeamViewer\DeviceManagementV2'
# This 32-bit path is for TeamViewer 32-bit being installed on a 64-bit system.
$TV32Bit = 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer\DeviceManagementV2'

# Determine which version of TeamViewer is installed based on where the registry keys are located. Either 64-bit or 32-bit.
try {
    $TeamViewerManagementID = Get-Item -Path $TV64Bit -ErrorAction Stop #Get TeamViewer ID from the registry for a 64-bit Client install
    Write-Host "[INFO] TeamViewer Architecture Installed: [64-bit]"
    #$tvArchitectureVersionInstalled = "64-bit"
    $tvRegSearchPath = $TV64Bit
} catch {
    try {
        $TeamViewerManagementID = Get-Item -Path $TV32Bit -ErrorAction Stop #Get TeamViewer ID from the registry for a 32-bit Client install
        Write-Host "[INFO] TeamViewer Architecture Installed: [32-bit]"
        #$tvArchitectureVersionInstalled = "32-bit"
        $tvRegSearchPath = $TV32Bit
    } catch {
        #$tvArchitectureVersionInstalled = "Not Installed"
        #$tvRegSearchPath = $null
        Write-Host "[INFO] TeamViewer is likely not installed. No registry keys were found at their expected location. Exiting..."
        
        Stop-Transcript -ErrorAction SilentlyContinue
        exit 0
    }
}

# Only try to grab the ManagementId if the device is currently managed. Exit if not managed
try {
    $TeamViewerUnmanaged = Get-ItemPropertyValue -Path $tvRegSearchPath -Name 'Unmanaged' -ErrorAction Stop
    Write-Host "[INFO] TeamViewer Management Status: [Unmanaged]"
    Write-Host "[INFO] TeamViewer is currently unmanaged. Exiting..."
    $TeamViewerManagementID = $null
} catch {
    Write-Host "[INFO] TeamViewer Management Status: [Managed]"
    try {
        $TeamViewerManagementID = (Get-ItemPropertyValue -Path $tvRegSearchPath -Name 'ManagementId' -ErrorAction Stop) -replace '[{}]'
        Write-Host "[INFO] TeamViewer Management ID:     [$TeamViewerManagementID]"
    } catch {
        Write-Host "[ERROR] The TeamViewer Management ID was not found in the Registry. This is unexpected because if the 'Unmanaged' key DOESN'T exist then a 'ManagementId' key SHOULD exist. The registry might have been manually altered to reach this state. Also note: under normal circumstances, expected behavior is that if TeamViewer has EVER been managed then it will retain the 'ManagementId' key it generated when it originally became managed. Even if it becomes unmanaged again later it will retain the 'ManagementId' key. Exiting..."
        $TeamViewerManagementID = $null
    }
}

# Exit if the PC's TeamViewer install isn't Managed
if ($null -eq $TeamViewerManagementID) {
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

########################################################################

# Talk to Microsoft Graph

Write-Host ""
Write-Host "[Part 2] Attempting to get the Assigned User for the device in Intune via Microsoft Graph..."

# Get Intune Device ID From registry
# https://www.modernendpoint.com/managed/Dynamically-Update-Primary-Users-on-Intune-Managed-Devices/
# I don't think this part needs any error checking because if the Intune Management Extension is working properly enough to run these scripts then I would imagine that this key would have to exist unless manually tampered with.
# Hopefully this assumption won't cause me problems later
$intuneDeviceIDRegPath = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Enrollments -Recurse -Include "MS DM Server"
$intuneDeviceID = Get-ItemPropertyValue -Path Registry::$intuneDeviceIDRegPath -Name EntDMID

Write-Host "[DEBUG] Intune Device ID: [$intuneDeviceID]"

$graphOAuthTokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Get OAuth 2.0 token
$graphOAuthTokenBody = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $clientId
    client_secret = $clientSecret
}

$graphOAuthTokenResponse = $null
$graphOAuthToken = $null

Write-Host "[INFO] Attempting to get the OAuth token for Microsoft Graph..."

# Try to get an OAuth Token for Microsoft Graph
try {
    $graphOAuthTokenResponse = Invoke-RestMethod -Method Post -Uri $graphOAuthTokenUrl -ContentType "application/x-www-form-urlencoded" -Body $graphOAuthTokenBody -Verbose -ErrorAction Stop
    $graphOAuthToken = $graphOAuthTokenResponse.access_token
} catch {
    Write-Host "[ERROR] Failed to acquire the OAuth token for Microsoft Graph."
    Handle-APIRequestError -Error $_
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

#Write-Host "[DEBUG] Graph OAuth Token Response - Status Code: " $graphOAuthTokenResponse.StatusCode.value__

###################################

# Query Microsoft Graph for the managed device's userPrincipalName
$graphDeviceInfoUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$intuneDeviceID"

$graphDeviceInfoHeaders = @{
    Authorization = "Bearer $graphOAuthToken"
    Accept        = "application/json"
}

$graphDeviceInfoResponse = $null

Write-Host "[INFO] Attempting to query the Microsoft Graph API for the device info of '$intuneDeviceID'..."

# Try to get the Device Info for the device using Microsoft Graph
try {
    $graphDeviceInfoResponse = Invoke-RestMethod -Method Get -Uri $graphDeviceInfoUrl -Headers $graphDeviceInfoHeaders -Verbose -ErrorAction Stop
} catch {
    Write-Host "[ERROR] Encountered an error when querying the Microsoft Graph API for the device info of '$intuneDeviceID'."
    Handle-APIRequestError -Error $_
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

#Write-Host "[DEBUG] Graph Device Info Response - Status Code: " $graphDeviceInfoResponse.StatusCode.value__

$username = $null
$userPrincipalName = $null

# Extract userPrincipalName
$userPrincipalName = $graphDeviceInfoResponse.userPrincipalName

if ($null -eq $userPrincipalName) {
    Write-Host "[INFO] The 'userPrincipalName' key found for the device is null or empty. The device does not have an assigned user."
    
    # Append "-UNASSIGNED" to the device name for the device in TeamViewer if it isn't assigned to a user in Intune
    $desiredTVDeviceName = "$ComputerName-UNASSIGNED"
    
    Write-Host "[DEBUG] Current Computer Name:          [$ComputerName]"
    Write-Host "[DEBUG] Desired TeamViewer Device Name: [$desiredTVDeviceName]"
} else {
    # Get the username portion before the '@' symbol and convert to lowercase
    $username = $userPrincipalName.Split('@')[0].ToLower()
    
    # TO-DO: Might need to add logic to also remove other special characters but these 2 seemed the most likely to pop up
    # Remove the following special characters: ' and -
    $sanitizedUsername = $username -replace "[\'-]", ""
    
    # Append the username of the assigned user in Intune to the device name in TeamViewer
    $desiredTVDeviceName = "$ComputerName-$sanitizedUsername"
    
    # Output the userPrincipalName, username, and sanitized username
    Write-Host "[DEBUG] User Principal Name:            [$userPrincipalName]"
    Write-Host "[DEBUG] Username:                       [$username]"
    Write-Host "[DEBUG] Sanitized Username:             [$sanitizedUsername]"
    Write-Host "[DEBUG] Current Computer Name:          [$ComputerName]"
    Write-Host "[DEBUG] Desired TeamViewer Device Name: [$desiredTVDeviceName]"
}

# Output the full JSON response in a readable format
$graphJSONResponse = $graphDeviceInfoResponse | ConvertTo-Json -Depth 10
Write-Host "[DEBUG] Full Output of Microsoft Graph Device Info Request:"
Write-Host $graphJSONResponse

########################################################################

# Do the TeamViewer API Stuff

Write-Host ""
Write-Host "[Part 3] Attempting to get the Device Info of the device in TeamViewer..."

#$tvURL = "https://webapi.teamviewer.com/api/v1/managed/devices/"
#$tvURL += "$TeamViewerManagementID"

$tvURL = "https://webapi.teamviewer.com/api/v1/managed/devices/$TeamViewerManagementID"

$tvHeaders = @{
    Authorization = "Bearer $tvAPIToken"
    Accept        = "application/json"
}

#Write-Host "[DEBUG] TeamViewer API Request URL: [$tvURL]"
# Get the device in TeamViewer API by the device's ManagementId using the managed devices endpoint

$tvDeviceInfoResponse = $null
$tvDeviceInfoResponseStatusCode = $null
$tvDeviceInfoResponseContent = $null

# Do the thing here
try {
    # POSSIBLE TO-DO: I should probably change this to use Invoke-RestMethod or switch the others to use Invoke-WebRequest for consistency
    #$tvDeviceInfoResponse = Invoke-WebRequest -Method Get -Uri $tvURL -UseBasicParsing -Headers $tvHeaders -Verbose
    $tvDeviceInfoResponse = Invoke-RestMethod -Method Get -Uri $tvURL -Headers $tvHeaders -Verbose
} catch {
    #Write-Host ""
    Write-Host "[ERROR] Encountered an error when querying the device info for '$TeamViewerManagementID' in TeamViewer."
    Handle-APIRequestError -Error $_
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

#$tvDeviceInfoResponseStatusCode = $tvDeviceInfoResponse.StatusCode
#Write-Host "[DEBUG] Status Code: $tvDeviceInfoResponseStatusCode"

#$tvDeviceInfoResponseContent = $tvDeviceInfoResponse.Content
#Write-Host "[DEBUG] Response Content: $tvDeviceInfoResponseContent"

#if ($tvDeviceInfoResponse.StatusCode -ne 200) {
    #Write-Host "[ERROR] Unexpected status code was given when attempting to get the device info for '$TeamViewerManagementID' in TeamViewer."
    #Write-Host "[INFO] Status Code: " $tvDeviceInfoResponse.StatusCode
    #$tvDeviceInfoUnexpectedResponse = $tvDeviceInfoResponse.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
    #Write-Host "[DEBUG] Unexpected Response:"
    #Write-Host $tvDeviceInfoUnexpectedResponse
    
    #Stop-Transcript -ErrorAction SilentlyContinue
    #exit 0
#}

#$tvDeviceInfo = $tvDeviceInfoResponse.Content | ConvertFrom-Json
#$tvFullJSONResponse = $tvDeviceInfoResponse.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
#$currentTVDeviceName = $tvDeviceInfo.name

#Write-Host "[DEBUG] Full TeamViewer Device Info:"
#Write-Host $tvFullJSONResponse
#Write-Host ""

#$tvDeviceInfo = $tvDeviceInfoResponse.Content | ConvertFrom-Json
$tvDeviceInfoFullJSONResponse = $tvDeviceInfoResponse | ConvertTo-Json -Depth 10
$currentTVDeviceName = $tvDeviceInfoResponse.name

Write-Host "[DEBUG] Full TeamViewer Device Info:"
Write-Host $tvDeviceInfoFullJSONResponse
Write-Host ""

#Check if names match
if ($currentTVDeviceName -eq $desiredTVDeviceName) {
    Write-Host "[NO ACTION NEEDED] TeamViewer Device Name is up to date."
    Write-Host "[INFO] Computer Name:                            [$ComputerName]"
    Write-Host "[INFO] Assigned Username (if found):             [$username]"
    Write-Host "[INFO] Assigned Username (Sanitized) (if found): [$sanitizedUsername]"
    Write-Host "[INFO] Current TeamViewer Device Name:           [$currentTVDeviceName]"
    Write-Host "[INFO] Desired TeamViewer Device Name:           [$desiredTVDeviceName]"
} else {
    Write-Host "[ACTION NEEDED] TeamViewer Device Name is out of date."
    Write-Host "[INFO] Computer Name:                            [$ComputerName]"
    Write-Host "[INFO] Assigned Username (if found):             [$username]"
    Write-Host "[INFO] Assigned Username (Sanitized) (if found): [$sanitizedUsername]"
    Write-Host "[INFO] Current TeamViewer Device Name:           [$currentTVDeviceName]"
    Write-Host "[INFO] Desired TeamViewer Device Name:           [$desiredTVDeviceName]"

    # Exiting a detection script with an error code of 1 triggers the remediation script to run
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

Stop-Transcript -ErrorAction SilentlyContinue
exit 0