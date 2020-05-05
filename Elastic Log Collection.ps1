param(
    [Parameter(Mandatory = $true)][string]$CbAction,
    [Parameter(Mandatory = $true)][string]$CbDeviceId,
    [Parameter()][string]$PolicyNameOrId,
    [Parameter()][string]$TargetPath,
    [Parameter()][string]$OutFilePath,
    [Parameter()][string]$ProcId,
    [Parameter()][string]$Offset,
    [Parameter()][string]$ByteCount,
    [Parameter()][switch]$Test
)

# Trap for an exception during the Script
Trap [Exception]
{
    if ($PSItem.ToString() -eq "ExecutionFailure")
	{
        $result_close = CloseCbSession $parms_id $parms_sessionid
		exit 1
	}
    elseif ($PSItem.ToString() -eq "DeviceFailure")
	{
		exit 1
	}
	else
	{
        $result_close = CloseCbSession $parms_id $parms_sessionid		
        write-error $("Trapped: $_")
		write-host "Aborting Operation."
		exit
	}
}

# Function to fetch saved parameter data
function Get-ConfigFileData
{
	if (!(Test-Path -Path $global:ConfigurationFilePath))
	{
		write-host "Config File Not Found. Please run 'Create CB Defense Configuration File' action."
		write-error "Error: No Config File Found."
		throw "ExecutionFailure"
	}
	else
	{
		$ConfigFileContent = Import-Clixml -Path $global:ConfigurationFilePath
		$EncryptedAuthToken = $ConfigFileContent.AuthToken
        $EncryptedAPIHost = $ConfigFileContent.APIHost
		$global:PlainAuthToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($EncryptedAuthToken))))
        $global:PlainAPIHost = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($EncryptedAPIHost))))

        $global:AuthToken = $global:PlainAuthToken
        $global:APIHost = $global:PlainAPIHost
	}
}

$global:ConfigurationFilePath = "C:\Program Files\LogRhythm\SmartResponse Plugins\CBDefenseConfigFile.xml"

Get-ConfigFileData
[hashtable]$parms_hdr = @{ "Content-Type" = "application/json"; "X-Auth-Token" = $global:AuthToken }


#  ┌────────────────────────────────────────────────────────────┐
#  │	Params/Helper Functions 								│
#  └────────────────────────────────────────────────────────────┘

# =========== Global Parameters

[string]$parms_uriprefix        = $global:APIHost + '/integrationServices/v3/cblr/session'
[string]$parms_dvcuriprefix     = $global:APIHost + '/integrationServices/v3/device'
[string]$parms_uri              = $parms_uriprefix + '/' + $CbDeviceId
[string]$global:parms_id        = ""
[string]$global:parms_sessionid = ""
[string]$parms_status           = "NONE"
[bool]$flags_sopen              = $false

[System.Net.ServicePointManager]::Expect100Continue = $false

# =========== Global Misc Parameters (Can be tuned if desired)

[System.UInt32]$mparms_session_wait = 600				# Time span (in seconds) that the script will wait for the Cb Defense session to activate or close


# =========== Mini Helper Functions

# Mini function that converts objects into JSON strings
function oj([PSCustomObject]$o)
{
    $j = ConvertTo-Json -InputObject $o -Compress
    return $j
}

# Mini function that converts JSON into objects
function jo([string]$j)
{
    [PSCustomObject]$o = ConvertFrom-Json -InputObject $j
    return $o
}

# Mini function that converts a hashtable into JSON
function hj([hashtable]$h)
{
    $o = [PSCustomObject]$h
    $j = oj $o
    return $j
}

# =========== Main Helper Functions

# @@@@@@@@@@@ Create Session

function CreateCbSession()
{
    DebugPrint "Creating Cb Defense API session"
    Try{
        $resp_createsession = Invoke-RestMethod -Method Post -Uri $parms_uri -Headers $parms_hdr -Body $('{"sensor_id": '+$CbDeviceId+'}') -ErrorAction Ignore -DisableKeepAlive
    }
    Catch{
        [System.Threading.Thread]::Sleep(1000)
        Write-host $_
        Throw "DeviceFailure"
    }
   
    [System.Threading.Thread]::Sleep(1000)			# Session open request has been sent, wait for 1 second for response to populate
    
    if ($resp_createsession.status -ne "PENDING" -or $resp_createsession.status -eq "ACTIVE")
    {
        DebugPrint ("Session creation error: "+$resp_createsession.status)
        if($resp_createsession.status -eq "ACTIVE")
        {
            $parms_status = $resp_createsession.status
            $parms_id = $resp_createsession.id
            $parms_sessionid = ([string]($resp_createsession.id)).Split(':')[0]
            $global:parms_id = $parms_id
            $global:parms_sessionid = $parms_sessionid
            return $true
        }
        else{
            Write-Host "`nError creating Cb Defense session."
            throw (New-Object System.Exception "Error creating Cb Defense session")
        }
    }
    else
    {
        # Store session ID/ID number for further usage, as well as session status

        $parms_status = $resp_createsession.status
        $parms_id = $resp_createsession.id
        $parms_sessionid = ([string]($resp_createsession.id)).Split(':')[0]
        
        DebugPrint "Session open request rcv OK, waiting on session: ${parms_id}"

        # Wait for the session to activate

        $status_chk_count = 0

        while ($parms_status -eq "PENDING")
        {
            # If we've waited for the session to activate for longer than mparms_session_wait value, throw an error
            if ($status_chk_count -gt $mparms_session_wait)
            {
                DebugPrint "Waited longer than 600 seconds for session to activate, aborting"
                throw (New-Object System.Exception "Waited longer than 600 seconds for Cb Defense session to activate")
            }
            $parms_status = (Invoke-RestMethod -Method Get -Uri $($parms_uriprefix+'/'+$parms_id) -Headers $parms_hdr -ErrorAction Ignore).status
            #DebugPrint "Session ${parms_id} status: ${parms_status}"   # Print to debug every cycle
            [System.Threading.Thread]::Sleep(1000)
            $status_chk_count++
        }

        # If session status is any value other than "ACTIVE" at this point something has gone wrong with the session open request

        if ($parms_status -ne "ACTIVE")
        {
            DebugPrint "Session status should be ACTIVE, but is actually: ${parms_status}; Session failed to open."
            $flags_sopen = $false
            return $false
        }

        DebugPrint "Session opened and status set to ACTIVE. Session: ${parms_sessionid}"
        $flags_sopen = $true

        $global:parms_id = $parms_id
        [System.Threading.Thread]::Sleep(1000)
        $global:parms_sessionid = $parms_sessionid
        [System.Threading.Thread]::Sleep(1000)
        return $true
    }
}

# @@@@@@@@@@@ Close Session

function CloseCbSession($a_id,$a_sessionid)
{
    $parms_id = $a_id
    $parms_sessionid = $a_sessionid
    DebugPrint "Closing Cb Defense API session"
    $parms_status = (Invoke-RestMethod -Method Put -Uri $parms_uriprefix -Body $(hj @{ "session_id" = $parms_id; "status" = "CLOSE" }) -Headers $parms_hdr -ErrorAction Ignore -DisableKeepAlive).status

    [System.Threading.Thread]::Sleep(1000)

    $status_chk_count = 0

    while ($parms_status -ne "CLOSE")
    {
        if ($status_chk_count -gt $mparms_session_wait)
        {
            DebugPrint "Waited longer than ${mparms_session_wait} seconds for session to close, aborting"
            throw (New-Object System.Exception "Waited longer than ${mparms_session_wait} seconds for Cb Defense session to close")
        }
        $parms_status = (Invoke-RestMethod -Method Get -Uri $($parms_uriprefix+'/'+$parms_id) -Headers $parms_hdr -ErrorAction Ignore).status
        DebugPrint "Waiting for close: ${parms_status}"
        [System.Threading.Thread]::Sleep(2000)
    }
    
    DebugPrint "Session closed successfully, done"
    return $true
}

# @@@@@@@@@@@ GetCbCmdStatus

function GetCbCmdStatus($a_cmdid,$a_sessionid,$b_mode)
{
    $parms_cmduri = $($parms_uriprefix + '/' + $a_sessionid + '/command/' + $a_cmdid)
    #DebugPrint $parms_cmduri

    $cmd_status = Invoke-RestMethod -Method Get -Uri $parms_cmduri -Headers $parms_hdr -ErrorAction Ignore

    if ($cmd_status.status -eq "")
    {
        # This should typically never be returned
        return "UNKNOWN_STATUS"
    }

    DebugPrint $("Command status: "+$cmd_status.status)

    if ($b_mode -eq $true)
    {
        return $cmd_status
    }
    else
    {
        return $cmd_status.status
    }
}

# @@@@@@@@@@@ GetCbMemDumpStatus

function GetCbMemDumpStatus($a_cmdid,$a_sessionid,$b_mode)
{
    $parms_cmduri = $($parms_uriprefix + '/' + $a_sessionid + '/command/' + $a_cmdid)
    #DebugPrint $parms_cmduri

    $cmd_status = Invoke-RestMethod -Method Get -Uri $parms_cmduri -Headers $parms_hdr -ErrorAction Ignore

    #Format-List -InputObject $cmd_status
    if ($cmd_status.complete -ne $true -and $cmd_status.complete -ne $false)
    {
        # THROW ERROR HERE
        return "UNKNOWN_MEMDUMP_STATUS"
    }

    if ($b_mode -eq $true)
    {
        return $cmd_status
    }
    else
    {
        DebugPrint $("Memdump running: "+$cmd_status.dumping+"; % Done: "+$cmd_status.percentdone)
        return $cmd_status.complete
    }
}

# @@@@@@@@@@@ IsActionValid

function IsActionValid([string]$a)
{
    switch ($a)
    {
        "ProcessList"			{ return $true }
        "DirectoryList"         { return $true }
        "KillProcess"			{ return $true }
        "GetFile"				{ return $true }
        "DeleteFile"			{ return $true }
        "DumpMemory"			{ return $true }
        "DeviceStatus"			{ return $true }
        "ChangeDevicePolicy"	{ return $true }     
        default					{ return $false }
    }

    return $false
}

# @@@@@@@@@@@ DebugPrint

function DebugPrint($ds)
{
    [System.Diagnostics.Debug]::Write($([System.String])::Format("{0}: SRP-CbDefense: {1}", [System.DateTime]::Now.ToString("MM/mm/yy hh:mm:ss tt"), $ds))
    return
}

function Device-exists{
    $parms_dvcstatusuri = $parms_dvcuriprefix + "/" + $CbDeviceId 
    try{
        $cmd_result = Invoke-RestMethod -Method Get -Uri $parms_dvcstatusuri -Headers $parms_hdr -ErrorVariable err
    }catch{
        $ErrorMessage = $err.message 
        $ErrorArray= $ErrorMessage.split(",")
        $Message = $ErrorArray[2].split(":")[1]
        $Message=$Message.trimend("}")
        Write-Host $Message
        Throw "DeviceFailure"
    }
}

Device-exists

#  ┌────────────────────────────────────────────────────────────┐
#  │	Main Function 											│
#  └────────────────────────────────────────────────────────────┘

#clear

#*******************************************************************************************

if ($CbAction -eq "")
{
    throw (New-Object System.Exception "No action specified!")
    exit
}
else
{
    # Check to see if the selected action is valid

    if ((IsActionValid $CbAction) -eq $false)
    {
        # Action is invalid, throw exception

        throw (New-Object System.Exception "Invalid action specified")
    }
    else
    {
        # Action is valid; determine whether requested action is part of the "live response" API call set or the standard Cb Defense REST API set

        if ($CbAction -eq "DeviceStatus"-or $CbAction -eq "ChangeDevicePolicy")
        {
            # =========== Cb Defense REST API calls

            switch ($CbAction)
            {
                "DeviceStatus"
                {
                    DebugPrint 'Executing API call "device status"'
                    $parms_dvcstatusuri = ""

                    if ($CbDeviceId -eq "")
                    {
                        $parms_dvcstatusuri = $parms_dvcuriprefix
                    }
                    else
                    {
                        $parms_dvcstatusuri = $parms_dvcuriprefix + "/" + $CbDeviceId
                    }

                    $cmd_result = Invoke-RestMethod -Method Get -Uri $parms_dvcstatusuri -Headers $parms_hdr 

                    if ($cmd_result.success -ne "True")
                    {
                        Write-Host "Device status command error, message:" $cmd_result.message
                        Throw "ExecutionFailure"
                        break
                    }
                    else
                    {
                        $final_out = Format-List -InputObject $cmd_result.deviceInfo
                        $final_out
                        exit
                    }
                }
                "ChangeDevicePolicy"
                {
                    DebugPrint 'Executing API call "change device policy"'
                    $parms_dvcstatusuri = ""

                    $parms_dvcstatusuri = $parms_dvcuriprefix + "/" + $CbDeviceId
                    
                    try{
                        if($PolicyNameOrId -match '^\d+$'){
                            $cmd_result = Invoke-RestMethod -Method Patch -Uri $parms_dvcstatusuri -Headers $parms_hdr -Body $(hj @{ "policyId" = $PolicyNameOrId}) -ErrorVariable err
                        }else{
                            $cmd_result = Invoke-RestMethod -Method Patch -Uri $parms_dvcstatusuri -Headers $parms_hdr -Body $(hj @{ "policyName" = $PolicyNameOrId}) -ErrorVariable err
                        }

                        if ($cmd_result.success -eq "True"){
                            Write-Host "Policy successfully applied to Device"
                            exit
                        }                   
                    }catch{
                        $ErrorMessage = $err.message 
                        $ErrorArray= $ErrorMessage.split(",")
                        $Message = $ErrorArray[2].split(":")[1]
                        $Message= $Message.remove(1,1)
                        Write-Host "$Message $PolicyNameOrId"
                        Throw "ExecutionFailure"
                        break
                    }
                }
                default
                {
                    # This exception should never get thrown
                    throw (New-Object System.Exception "Invalid action specified")
                }
            }
        }
        else
        {
            # =========== Cb Defense Live Response API calls

            $result_open = CreateCbSession
            [System.Threading.Thread]::Sleep(1000)
            if ($result_open -ne $true)
            {
                throw (New-Object System.Exception "Unknown error creating Cb Defense API session")
            }
    
            $parms_cmduri = $($parms_uriprefix + '/' + $parms_id + '/command') 
    
            switch ($CbAction)
            {
                "ProcessList"
                {
                    DebugPrint 'Executing API call "process list"'
                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "process list" }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.status
                    while ($parms_cmdstatus -ne "complete" -and $parms_cmdstatus -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(1000)
                        DebugPrint "Command status: ${parms_cmdstatus}"   
                        $parms_cmdstatus = GetCbCmdStatus $parms_cmdid $parms_id $false
                    }
    
                    $cmd_result = GetCbCmdStatus $parms_cmdid $parms_id $true
    
                    if ($cmd_result.status -eq "error")
                    {
                        # Command error
                        Write-Host "`nProcess list error"
                        Throw "ExecutionFailure"
                        break
                    }
                    else
                    {
                        # Command success
                        $final_out = $(Format-List -InputObject $cmd_result.processes)
                        Write-Host "`nProcess list :-"
                        if ($final_out.Length -lt 4096)
                        {
                            echo $final_out
                        }
                        else
                        {
                            echo $($final_out.Substring(0,4095))
                        }
                        break
                    }
    
                    
                }
                "DirectoryList"
                {
                    DebugPrint 'Executing API call "directory list"'
                    if ($TargetPath -eq "")
                    {
                        Write-Host "`nNo target path specified."
                        Throw "ExecutionFailure"
                        break
                    }
                    elseif ($TargetPath -notmatch "^[a-zA-Z]:\\[\\\S|*\S]?.*$")
                    {
                        Write-Host "`nTarget path specified is not a valid Directory."
                        Throw "ExecutionFailure"
                        break
                    }
                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "directory list"; "object" = $TargetPath }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.status
                    while ($parms_cmdstatus -ne "complete" -and $parms_cmdstatus -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(1000)
                        DebugPrint "Command status: ${parms_cmdstatus}"   
                        $parms_cmdstatus = GetCbCmdStatus $parms_cmdid $parms_id $false
                    }
    
                    $cmd_result = GetCbCmdStatus $parms_cmdid $parms_id $true
    
                    if ($cmd_result.status -eq "error")
                    {
                        # Command error
                        Write-Host "`nDirectory list error"
                        Throw "ExecutionFailure"
                        break
                    }
                    else
                    {
                        # Command success
                        $final_out = $(Format-List -InputObject $cmd_result.files)
                        Write-Host "`nDirectory list :-"
                        if ($final_out.Length -lt 4096)
                        {
                            echo $final_out
                        }
                        else
                        {
                            echo $($final_out.Substring(0,4095))
                        }
                        break
                    }
                }
                "KillProcess"
                {
                    DebugPrint 'Executing API call "kill process"'
                    if ($ProcId -eq "" -or ([System.Text.RegularExpressions.Regex]::IsMatch($ProcId,"^\d+$")) -eq $false)
                    {
                        Write-Host "Process ID is missing or non-numeric"
                        Throw "ExecutionFailure"
                        break
                    }
                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "kill"; "object" = $ProcId }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.status
                    while ($parms_cmdstatus -ne "complete" -and $parms_cmdstatus -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(1000)
                        DebugPrint "Command status: ${parms_cmdstatus}"   
                        $parms_cmdstatus = GetCbCmdStatus $parms_cmdid $parms_id $false
                    }
    
                    $cmd_result = GetCbCmdStatus $parms_cmdid $parms_id $true
    
                    if ($cmd_result.status -eq "error")
                    {
                        # Command error
                        Write-Host "kill process error"
                        Throw "ExecutionFailure"
                        break
                    }
                    else
                    {
                        # Command success
                        Write-Host "Kill process success"
                        break
                    }
                }
                "GetFile"
                {
                    DebugPrint 'Executing API call "get file"'
                    $NumberPattern = "^[\d]+$"
                    if ($TargetPath -eq "" -or $OutFilePath -eq "" -or $Offset -eq "" -or $ByteCount -eq "")
                    {
                        Write-Host "One or more missing/invalid input parameters"
                        Throw "ExecutionFailure"
                    }
                    elseif($TargetPath -notmatch "^([a-zA-Z]\:|\\\\[^\/\\:*?<>|]+\\[^\/\\:*?<>|]+)(\\[^\/\\:*?<>|]+)+(\.[^\/\\:*?<>|]+)$")
                    {
                        Write-Host "`nTarget path should be valid file path."
                        Throw "ExecutionFailure"
                    }

                    If(!($Offset -match $NumberPattern -and $ByteCount -match $NumberPattern))
                    {
                        Write-Host "`nOffset and ByteCount should be integer."
                        Throw "ExecutionFailure"                       
                    }                         

                    #OutFile path check and Create if not exist
                    if (!(Test-Path -Path $OutFilePath))
	                {
		                New-Item -ItemType "directory" -Path $OutFilePath -Force | Out-null
	                }

                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "get file"; "object" = $TargetPath; "offset" = $Offset; "get_count" = $ByteCount }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.status
                    while ($parms_cmdstatus -ne "complete" -and $parms_cmdstatus -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(1000)
                        DebugPrint "Command status: ${parms_cmdstatus}"   
                        $parms_cmdstatus = GetCbCmdStatus $parms_cmdid $parms_id $false
                    }
    
                    $cmd_result = GetCbCmdStatus $parms_cmdid $parms_id $true
    
                    if ($cmd_result.status -eq "error")
                    {
                        # Command error
                        Write-Host "`nFile get error"
                        break
                    }
                    else
                    {    
                        DebugPrint "GetFile: Got file ID/information"
    
                        $parms_fileuri = $($parms_uriprefix + '/' + $parms_id + '/file/' + $cmd_result.file_id + '/content')
                        
                        DebugPrint "GetFile: Requesting raw file bytes"
                        
                        $TargetFile = ((($TargetPath -split ':')[1] -split '\\')[-1] -split '\.')[0]
                        $DateFormat = (Get-Date).tostring("yyyy-MM-dd-hh-mm-ss")
                        $File = $OutFilePath + '\' + $TargetFile + "_" + $DateFormat
                          
                        Invoke-RestMethod -Method Get -Uri $parms_fileuri -Headers $parms_hdr -ErrorAction Continue -OutFile $File
                        DebugPrint "GetFile: Raw file written to disk"
    
                        Write-Host "`nFile get success"
                        break
                    }
                }
                "DeleteFile"
                {
                    DebugPrint 'Executing API call "delete file"'
                    if ($TargetPath -eq "")
                    {
                        Write-Host "Target file path is missing/invalid"
                        Throw "ExecutionFailure"
                        break
                    }
                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "delete file"; "object" = $TargetPath }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.status
                    while ($parms_cmdstatus -ne "complete" -and $parms_cmdstatus -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(1000)
                        DebugPrint "Command status: ${parms_cmdstatus}"   
                        $parms_cmdstatus = GetCbCmdStatus $parms_cmdid $parms_id $false
                    }
    
                    $cmd_result = GetCbCmdStatus $parms_cmdid $parms_id $true
    
                    if ($cmd_result.status -eq "error")
                    {
                        # Command error
                        Write-Host "file not deleted"
                        Throw "ExecutionFailure"
                        break
                    }
                    else
                    {
                        # Command success
                        Write-Host "file deleted"
                        break
                    }
                }
                "DumpMemory"
                {
                    DebugPrint 'Executing API call "memdump"'
                    if ($OutFilePath -eq "")
                    {
                        Write-Host "Output file path is missing/invalid"
                        Throw "ExecutionFailure"
                        break
                    }
                    $cmd_result = Invoke-RestMethod -Method Post -Uri $parms_cmduri -Headers $parms_hdr -Body $(hj @{ "session_id" = $parms_id; "name" = "memdump"; "object" = $OutFilePath }) -ErrorAction Ignore -DisableKeepAlive
                    $parms_cmdid = $cmd_result.id
                    $parms_cmdstatus = $cmd_result.complete
                    while ($parms_cmdstatus -ne $true -and $cmd_result -ne "error")
                    {
                        [System.Threading.Thread]::Sleep(5000)
                        $parms_cmdstatus = GetCbMemDumpStatus $parms_cmdid $parms_id $false
                    }
    
                    # This returns a simple "True" or "False"
    
                    $cmd_result = GetCbMemDumpStatus $parms_cmdid $parms_id $false
                    if ($cmd_result -eq $true)
                    {
                        Write-Host "memory dump success"
                        break
                    }
                    else
                    {
                        Write-Host "memory dump error"
                        Throw "ExecutionFailure"
                        break
                    }
                }
                default
                {
                    Write-Host "No Cb Defense action specified"
                    Throw "ExecutionFailure"
                    break
                }
            }
    
            $result_close = CloseCbSession $parms_id $parms_sessionid
            exit

        }
    }
}
# SIG # Begin signature block
# MIIcdQYJKoZIhvcNAQcCoIIcZjCCHGICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUCohxEAPKtKArAOzOvK3R7g3Q
# mSagghebMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTKMIIDsqADAgECAhA7fcSpOOvoChwkFo65IyOmMA0GCSqGSIb3DQEBCwUAMH8x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMg
# Q2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE3MDQwNDAwMDAwMFoX
# DTIwMDQwNDIzNTk1OVowYjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRv
# MRAwDgYDVQQHDAdCb3VsZGVyMRYwFAYDVQQKDA1Mb2dSaHl0aG0gSW5jMRYwFAYD
# VQQDDA1Mb2dSaHl0aG0gSW5jMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEArr9SaqNn81S+mF151igpNeqvzWs40uPSf5tXu9iQUqXCWx25pECOcNk7W/Z5
# O9dXiQmdIvIFF5FqCkP6rzYtKx3OH9xIzoSlOKTxRWj3wo+R1vxwT9ThOvYiz/5T
# G5TJZ1n4ILFTd5JexoS9YTA7tt+2gbDtjKLBorYUCvXv5m6PREHpZ0uHXGCDWrJp
# zhiYQdtyAfxGQ6J9SOekYu3AiK9Wf3nbuoxLDoeEQ4boFW3iQgYJv1rRFA1k4AsT
# nsxDmEhd9enLZEQd/ikkYrIwkPVN9rPH6B+uRsBxIWIy1PXHwyaCTO0HdizjQlhS
# RaV/EzzbyTMPyWNluUjLWe0C4wIDAQABo4IBXTCCAVkwCQYDVR0TBAIwADAOBgNV
# HQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N2LnN5bWNiLmNv
# bS9zdi5jcmwwYQYDVR0gBFowWDBWBgZngQwBBAEwTDAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUHAQEESzBJ
# MB8GCCsGAQUFBzABhhNodHRwOi8vc3Yuc3ltY2QuY29tMCYGCCsGAQUFBzAChhpo
# dHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNydDAfBgNVHSMEGDAWgBSWO1PweTOXr32D
# 7y4rzMq3hh5yZjAdBgNVHQ4EFgQUf2bE5CWM4/1XmNZgr/W9NahQJkcwDQYJKoZI
# hvcNAQELBQADggEBAHfeSWKiWK1eI+cD/1z/coADJfCnPynzk+eY/MVh0jOGM2dJ
# eu8MBcweZdvjv4KYN/22Zv0FgDbwytBFgGxBM6pSRU3wFJN9XroLJCLAKCmyPN7H
# IIaGp5RqkeL4jgKpB5R6NqSb3ES9e2obzpOEvq49nPCSCzdtv+oANVYj7cIxwBon
# VvIqOZFxM9Bj6tiMDwdvtm0y47LQXM3+gWUHNf5P7M8hAPw+O2t93hPmd2xA3+U7
# FqUAkhww4IhdIfaJoxNPDjQ4dU+dbYL9BaDfasYQovY25hSe66a9S9blz9Ew2uNR
# iGEvYMyxaDElEXfyDSTnmR5448q1jxFpY5giBY0wggTTMIIDu6ADAgECAhAY2tGe
# Jn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHKMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5l
# dHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1
# dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVi
# bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0wNjEx
# MDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdv
# cmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhv
# cml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGlj
# IFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWeYAyq50s7Ttx8vDxFHLsr4P4p
# AvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3S7P+j34HV+zvQ9tmYhVhz2AN
# pNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ2ENjalJL0o/ocFFN0Ylpe8dw
# 9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE75C55ADk3Tq1Gf8CuvQ87uCL
# 6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6sKlLHj9UESeSNY0eIPGmDy/5H
# vSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80h5aK7lPoJRUCAwEAAaOBsjCB
# rzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARh
# MF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvD
# z4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdp
# ZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQAD
# ggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSnoHgSrWIORXBkxeeXZi2YCX5f
# r9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjmBpFAGLn4we3f20Gq4JYgyc1k
# FTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpYT2DKfoJqCwKqJRc5tdt/54Rl
# KpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh9BFvELWV/OdCBTLbzp1RXii2
# noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2GdpxEevaVXPZdMggzpFS2GD9o
# XPJCSoU4VINf0egs8qwR1qjtY2owggVZMIIEQaADAgECAhA9eNf5dklgsmF99PAe
# yoYqMA0GCSqGSIb3DQEBCwUAMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVy
# aVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4
# BgNVBAsTMShjKSAyMDA2IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQg
# dXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDMgUHVibGljIFByaW1h
# cnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHNTAeFw0xMzEyMTAwMDAwMDBa
# Fw0yMzEyMDkyMzU5NTlaMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4MeABavLLHSCMTXaJNR
# YB5x9uJHtNtYTSNiarS/WhtR96MNGHdou9g2qy8hUNqe8+dfJ04LwpfICXCTqdpc
# DU6kDZGgtOwUzpFyVC7Oo9tE6VIbP0E8ykrkqsDoOatTzCHQzM9/m+bCzFhqghXu
# PTbPHMWXBySO8Xu+MS09bty1mUKfS2GVXxxw7hd924vlYYl4x2gbrxF4GpiuxFVH
# U9mzMtahDkZAxZeSitFTp5lbhTVX0+qTYmEgCscwdyQRTWKDtrp7aIIx7mXK3/nV
# jbI13Iwrb2pyXGCEnPIMlF7AVlIASMzT+KV93i/XE+Q4qITVRrgThsIbnepaON2b
# 2wIDAQABo4IBgzCCAX8wLwYIKwYBBQUHAQEEIzAhMB8GCCsGAQUFBzABhhNodHRw
# Oi8vczIuc3ltY2IuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwbAYDVR0gBGUwYzBh
# BgtghkgBhvhFAQcXAzBSMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LnN5bWF1dGgu
# Y29tL2NwczAoBggrBgEFBQcCAjAcGhpodHRwOi8vd3d3LnN5bWF1dGguY29tL3Jw
# YTAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2IuY29tL3BjYTMtZzUu
# Y3JsMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMC
# AQYwKQYDVR0RBCIwIKQeMBwxGjAYBgNVBAMTEVN5bWFudGVjUEtJLTEtNTY3MB0G
# A1UdDgQWBBSWO1PweTOXr32D7y4rzMq3hh5yZjAfBgNVHSMEGDAWgBR/02Wnwt3s
# u/AwCfNDOfoCrzMxMzANBgkqhkiG9w0BAQsFAAOCAQEAE4UaHmmpN/egvaSvfh1h
# U/6djF4MpnUeeBcj3f3sGgNVOftxlcdlWqeOMNJEWmHbcG/aIQXCLnO6SfHRk/5d
# yc1eA+CJnj90Htf3OIup1s+7NS8zWKiSVtHITTuC5nmEFvwosLFH8x2iPu6H2aZ/
# pFalP62ELinefLyoqqM9BAHqupOiDlAiKRdMh+Q6EV/WpCWJmwVrL7TJAUwnewus
# GQUioGAVP9rJ+01Mj/tyZ3f9J5THujUOiEn+jf0or0oSvQ2zlwXeRAwV+jYrA9zB
# UAHxoRFdFOXivSdLVL4rhF4PpsN0BQrvl8OJIrEfd/O9zUPU8UypP7WLhK9k8tAU
# ITGCBEQwggRAAgEBMIGTMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEw
# MC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENB
# AhA7fcSpOOvoChwkFo65IyOmMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQdk3wqFvIkOz/h/ElF
# MhrQ9NjV8jANBgkqhkiG9w0BAQEFAASCAQApObogS7agH52DN79Ylm3qB6XUFEJw
# X+62IQHsZU7wHbqrG6VW3f1IbFgePzbsRvt+y24a3gXz2O98R+QD7R3vkZ8fVsIZ
# HlFlnWBax+weNB/i2J2dw2Rh3ilyHTQTV1ME4TWG9rWGxfuCqI+JvLyTo5UYyFIz
# COwjnSCvN2qMN5B0MEktF1n4MvvUgtHORfl8LD+JsUJWhqFfm8PMo65SSIYIEPIn
# Wws/6jZAV8pWzi+shvz0gxB0nfwc9hrYCC7AVFPeMVhYdsEFgnPME96rlyypkZJp
# tquM5dox/epjdJDMx60K9l+bUfpfhK7AHF/1E4+YHzrxm7UeSMrjB9s6oYICCzCC
# AgcGCSqGSIb3DQEJBjGCAfgwggH0AgEBMHIwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzICEA7P9DjI/r81bgTYapgbGlAwCQYF
# Kw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF
# MQ8XDTE5MDcxODA3MjQ0NVowIwYJKoZIhvcNAQkEMRYEFCgxLzXYJGJ16uTBUlXF
# 1NEqkJZeMA0GCSqGSIb3DQEBAQUABIIBAC7tjlh0S0DfhD363OsWAF4iYIrPaLlU
# rUwQzAljPyOafXooXRdf5qeE7jhq5+zzb7BhTBr4Zk5M8K5/gWT2QYH9EZIyJFQZ
# VbeamR2rOPyPpOGJaCBsYxVLDmeBP00WcmvBAYibrTuDW6gflK6D5jXpXbo5Wwm0
# cKA3sxmL1F/+9W8fNMThIhNwPEm/Ka13LXnIwbE+qsMQ9Fe22aLCB4yO/Qd1iOGu
# GPfuke6KTeogSTdbBDHNSJtL+mTgn6ynqBfHkvKDE4NvKdBHTS3zZN+Q/BLcKV96
# tV16i0HRzM7beBDjaR1PQgmwWx8r5a9YaEpOzqMkKLOFJIzDoGxxDUY=
# SIG # End signature block
