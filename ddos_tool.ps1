$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ClearHost()

# Display menu and get user's choice
do {
    Clear-Host
    Write-Host "                                    #######################################################" -ForegroundColor Red
    Write-Host "                                    ##### PLEASE SNAPSHOT THE SERVER BEFORE MODIFYING ####" -ForegroundColor Red
    Write-Host "                                    #######################################################" -ForegroundColor Red
    Write-host 
    Write-Host "                                                    RDP&DDoS Tool" -ForegroundColor Red
    Write-Host ""
    Write-Host ""
    Write-Host "                                                 Select an option:"
    Write-Host "                                                 1. RDP malicious IPs"
    Write-Host "                                                 2. IIS malicious IPs"
    Write-Host "                                                 3. IPAbusedb API"
    Write-Host "                                                 4. Internal Firewall block"
    Write-Host "                                                 5. Change RDP port"
    Write-Host "                                                 6. Exit"
    Write-Host ""
    Write-Host ""

    $choice = Read-Host "                             Enter option number"

    switch ($choice) {
        "1" {
            ##### RDP Malicious IPs ######
            ##############################
            $now = Get-Date
            $TimeVar = Read-Host "Enter number of days to check:   "
            $TimeChosen = $now.AddDays(-$TimeVar)

            $events = Get-EventLog -LogName Security -InstanceId 4625 | Where-Object {$_.TimeGenerated -ge $TimeChosen}
            $ipRegex = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

            $ipCounts = @{}
            foreach ($event in $events) {
                $message = $event.Message
                if ($message -match $ipRegex) {
                    $ip = $Matches[0]
                    if ($ipCounts.ContainsKey($ip)) {
                        $ipCounts[$ip] += 1
                    } else {
                        $ipCounts[$ip] = 1
                    }
                }
            }

            # Sort IP addresses by count in ascending order
            $sortedIPs = $ipCounts.GetEnumerator() | Sort-Object Value
            cls
            Write-Host ""
            Write-Host ""
            Write-Host ""

            foreach ($entry in $sortedIPs) {
                $ip = $entry.Key
                $count = $entry.Value
                Write-Host ("{0,-15}{1}" -f "   IP address:", $ip) -ForegroundColor Yellow
                Write-Host ("{0,-15}{1}" -f "   Count:", $count) -ForegroundColor Green
                Write-Host ("{0,-15}" -f "") -ForegroundColor Gray
            }

            # Export the results to the specified text file
            $outputFilePath = Join-Path $PSScriptRoot "output_RDP.txt"
            $sortedIPs | ForEach-Object { "$($_.Key)" } | Out-File -FilePath $outputFilePath -Force
            Write-Host "Results exported to $outputFilePath" -ForegroundColor Cyan
            pause
        } 

        "2" {
            ##### IIS Malicious IPs #####
            #############################
            $logFilePath = Read-Host "Enter log FULL path (c:\path\to\file.log)"
            $currentDirectory = Get-Location
            $outputFilePath = Join-Path $currentDirectory "output_IIS.txt"
            $sourceIpAddressPattern = "(?<=\s)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=\sHTTP)"

            $logContent = Get-Content -Path $logFilePath

            $ipCounts = @{}

            $logContent | ForEach-Object {
                $match = [regex]::Match($_, $sourceIpAddressPattern)
                if ($match.Success) {
                    $ip = $match.Value
                    $ipCounts[$ip]++
                }
            }

            $ipCounts.GetEnumerator() | ForEach-Object {
                Write-Host ("IP: {0}" -f $_.Key) -ForegroundColor Yellow
                Write-Host ("Count: {0}" -f $_.Value) -ForegroundColor Green
                Write-Host ""  
            }

            $uniqueIps = $ipCounts.Keys | Out-File -FilePath $outputFilePath

            Write-Host "Results exported to $outputFilePath" -ForegroundColor Cyan
            pause
        } 

        "3" {
            ##### IPabusedb API #####
            #########################
            $ErrorActionPreference = "SilentlyContinue"
            Param(
                [Parameter(Mandatory=$False)]
                [AllowEmptyString()]
                [String]$Categories,

                [Parameter(Mandatory=$False)]
                [AllowEmptyString()]
                [String]$Comment
            )

            # Define AbuseIPDB API key
            $APIKey = Read-Host "Enter your AbuseIPDB API Key"

            # List to store IP addresses
            $IPList = @()

            # Get user input for IP addresses
            do {
                $IPInput = Read-Host -Prompt "Enter an IP address or press Enter to finish."

                # Add entered IP to the list
                if ($IPInput -ne "") {
                    $IPList += $IPInput
                }
            } while ($IPInput -ne "")

            Write-Output "------------------------"
            # Begin script execution for each entered IP address
            foreach ($IP in $IPList) {
                $Error.Clear()

                $Header = @{
                    'Key' = $APIKey;
                }

                # If Categories and Comment are empty, the call must be to check
                If (([string]::IsNullOrEmpty($Categories)) -and ([string]::IsNullOrEmpty($Comment))){
                    $URICheck = "https://api.abuseipdb.com/api/v2/check"
                    $BodyCheck = @{
                        'ipAddress' = $IP;
                        'maxAgeInDays' = '90';
                        'verbose' = '';
                    }

                    Try {
                        # GET abuse confidence score and set status if successful
                        $AbuseIPDB = Invoke-RestMethod -Method GET $URICheck -Header $Header -Body $BodyCheck -ContentType 'application/json; charset=utf-8' 
                        $StatusNum = "200"
                        $ConfidenceScore = $AbuseIPDB.data.abuseConfidenceScore
                    }
                    Catch {
                        # If error, capture status number from the message
                        $ErrorMessage = $_.Exception.Message
                        [regex]$RegexErrorNum = "\d{3}"
                        $StatusNum = ($RegexErrorNum.Matches($ErrorMessage)).Value    
                    }

                    $Response = @{
                        'Country Code' = $AbuseIPDB.data.countryCode
                        'Total Reports' = $AbuseIPDB.data.totalReports
                        'Usage Type' = $AbuseIPDB.data.usageType
                    }

                    # Output the result for the current IP
                    Write-Output "Results for IP: $IP"

                    # Check if Confidence Score is over 15 and mark output in red
                    if ($ConfidenceScore -gt 15) {
                        Write-Host "Confidence Score: $ConfidenceScore" -ForegroundColor Red
                        Write-Host "IP has been registered to output file!" -ForegroundColor red
                        Add-Content -Path 'output_AbuseIPdb.txt' -Value ($AbuseIPDB.data.ipAddress -join '')
                    } else {
                        Write-Output "Confidence Score: $ConfidenceScore"
                    }

                    $Response | Format-Table -AutoSize
                    Write-Output "------------------------"
                }
            }

            Write-Output ""
            Write-Output ""
            Write-Host "IPs with confidence score over 15% have been written to an output file 'output_AbuseIPdb.txt'" -ForegroundColor Cyan
            Write-Output ""

            pause
        } 

        "4" {
            ##### Internal Firewall block ######
            ####################################
            $ErrorActionPreference = "SilentlyContinue"
            param (
                [string]$action = "Block"
            )

            $ruleName = "Block IP Address"
            $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

            if ($existingRule) {
                Write-Host "Firewall rule $ruleName already exists. Adding IP addresses to existing rule..."

                $rule = New-Object -ComObject HNetCfg.FwPolicy2
                $existingRule = $rule.Rules | Where-Object { $_.Name -eq $ruleName }

                $ipAddresses = @()
                while ($true) {
                    $ipAddress = Read-Host "Enter an IP address (press Enter to finish)"
                    if ($ipAddress -eq "") {
                        break
                    }
                    $ipAddresses += $ipAddress
                }

                $existingRule.RemoteAddresses += "," + ($ipAddresses -join ',')
                Write-Host ""
                Write-Host ""
                Write-Host "                                    IPs were successfully blocked" -ForegroundColor Cyan
                pause
            } else {
                $ErrorActionPreference = "SilentlyContinue"
                Write-Host "Firewall rule $ruleName does not exist. Creating new rule..."

                $rule = New-Object -ComObject hnetcfg.fwpolicy2
                $newRule = New-Object -ComObject HNetCfg.FWRule

                $newRule.Name = $ruleName
                $newRule.Action = if ($action -eq "Block") { 0 } else { 1 }
                $newRule.Direction = 1
                $newRule.Enabled = $true

                $ipAddresses = @()
                while ($true) {
                    $ipAddress = Read-Host "Enter an IP address (press Enter to finish)"
                    if ($ipAddress -eq "") {
                        break
                    }
                    $ipAddresses += $ipAddress
                }
                $newRule.RemoteAddresses = $ipAddresses -join ','

                $rule.Rules.Add($newRule)
                Write-Host ""
                Write-Host ""
                Write-Host "                                    IPs were successfully blocked" -ForegroundColor Cyan
                pause
            }
        } 

        "5" {
            ##### Change RDP Port ######
            ############################
            $NewRDPPort = Read-Host "Enter New RDP port:   "

            # Validate the port number (optional)
            if ($NewRDPPort -lt 1 -or $NewRDPPort -gt 65535) {
                Write-Host "Invalid port number. Please choose a port between 1 and 65535."
                exit
            }

            # Define the registry key path for RDP port
            $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

            # Set the new RDP port in the registry
            Set-ItemProperty -Path $RegistryPath -Name "PortNumber" -Value $NewRDPPort

            Write-Host "RDP port successfully changed to $NewRDPPort."
            $RDPfirewallrule = "Custom RDP Port"
            New-NetFirewallRule -DisplayName $RDPfirewallrule -Direction Inbound -Protocol TCP -LocalPort $NewRDPPort -Action Allow
            Write-Host "Firewall rule '$RDPfirewallrule' added for port $NewRDPPort."
            Write-Host "Restarting service in... "

            $i = 5
            do {
                Write-Host $i
                Sleep 1
                $i--
            } while ($i -gt 0)

            Restart-Service -Name TermService -Force
        } 

        "6" {
            ###### EXIT CODE + DELETE EVERYTHING ######
            ###########################################
            Write-Host "Exiting the script."

            Write-Host "File self-destruct in .."
            function Delete() {
                $Invocation = (Get-Variable MyInvocation -Scope 1).Value
                $Path = Join-Path -Path $PSScriptRoot -ChildPath "output_*.txt"
                $Path_script = Join-Path -Path $PSScriptRoot -ChildPath "DDoS_Tool.ps1"
                Remove-Item $Path -force
                Remove-Item $Path_script -Force
            }

            $i = 3

            do {
                Write-Host $i
                Sleep 1
                $i--
            } while ($i -gt 0)

            Write-Host "                                Kaboom"
            Delete
            Start-Sleep 2

            exit
        }

        Default {
            Write-Host "Invalid option. Please select a valid option."
            Read-Host "Press Enter to continue..."
        }
    }
} while ($true)

