Function Get-UserApplication {
    <#
    .SYNOPSIS
    Gets list of local user apps from hkcu registry for all users

    .DESCRIPTION
    Gets list of local user apps from hkcu registry for all users


        
#>
    [CmdletBinding()]
    [alias("Get-UserApp")]
    Param()

    # Regex pattern for SIDs to exclude
    $Excl = '\.DEFAULT|S-1-5-18|S-1-5-19|S-1-5-20|.+_Classes'

    Try {
        # Get Username, SID, and location of ntuser.dat for all users
        $ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | 
            Where-Object { $_.PSChildName -notmatch $Excl } | 
                Select-Object  @{name = "SID"; expression = { $_.PSChildName } }, 
        @{name = "UserHive"; expression = { "$($_.ProfileImagePath)\ntuser.dat" } }, 
        @{name = "Username"; expression = { $_.ProfileImagePath -replace '^(.*[\\\/])', '' } }
     
        # Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
        $LoadedHives = Get-ChildItem Registry::HKEY_USERS | 
            Where-Object { $_.PSChildname -notmatch $Excl } | 
                Select-Object @{name = "SID"; expression = { $_.PSChildName } }
     
        # Get all users that are not currently logged
        If ($LoadedHives) {
            $LoadedHivesSidPattern = ($LoadedHives.SID | ForEach-Object { [regex]::Escape($_) } ) -join '|'
            $UnloadedHives = $ProfileList.SID | Where-Object { $_ -notmatch $LoadedHivesSidPattern }
        }
    }
    Catch {
        Write-Error $_ -Ea $ErrorActionPreference
        return
    }

    # Loop through each profile on the machine
    Foreach ($Profile in $ProfileList) {
        Try {
            # Load User ntuser.dat if it's not already loaded
            If ($UnloadedHives.SID -contains $Profile.SID) {
                $null = & reg load HKU\$($Profile.SID) $($Profile.UserHive) 2>&1
            }
     
            $UserAppPaths = @(
                "Registry::HKEY_USERS\$($Profile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )

            $UserAppPath64BitOs = "Registry::HKEY_USERS\$($Profile.SID)\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            If ( (Test-Path -Path $UserAppPath64BitOs -Ea 0) ) {
                $UserAppPaths += $UserAppPath64BitOs
            }
    
            ForEach ($UserAppPath in $UserAppPaths) {
                If (Test-Path -Path $UserAppPath -Ea 0) {
                    $SelObjParams = @{
                        Property = @(
                            # Remove invalid control chars to prevent RMM from falsely reporting no output,
                            # and to prevent weird behavior in other areas.
                            @{n = 'DisplayName'; e = { ($_.DisplayName -replace '[^\u001F-\u007F]', '') } },
                            @{n = 'DisplayVersion'; e = { ($_.DisplayVersion -replace '[^\u001F-\u007F]', '') } },
                            @{n = 'Publisher'; e = { ($_.Publisher -replace '[^\u001F-\u007F]', '') } },
                            'InstallDate',
                            'InstallLocation',
                            'UninstallString',
                            'QuietUninstallString',
                            'SystemComponent',
                            'NoRemove',
                            'NoRepair',
                            'PSChildName',
                            'PSPath',
                            'PSParentPath'
                            #@{n = 'UserProfile'; e = { ($Profile.UserName) } } 
                        )
                    }
                    Get-ItemProperty -Path $UserAppPath -ErrorAction Stop | Select-Object @SelObjParams
                }
            }
        }
        Catch {
            Write-Error $_ -Ea $ErrorActionPreference
        }
        Finally {
            # Unload ntuser.dat        
            If ($UnloadedHives.SID -contains $Profile.SID) {
                ### Garbage collection and closing of ntuser.dat ###
                [gc]::Collect()
                $null = & reg unload HKU\$($Profile.SID) 2>&1
            }
        }
    }
}

Function Get-InstalledApplication {
    <#
        .SYNOPSIS
        Gets list of installed apps from registry
    
        .DESCRIPTION
        Gets list of installed apps from registry
        Option to include all user installed apps as well (e.g. Teams, OneDrive)

        .EXAMPLE
        # Get all apps and export to csv
        Get-InstalledApplication | Export-Csv

        .EXAMPLE
        # Get all apps, Include system components and user-installed apps
        Get-InstalledApplication -IncludeSystemComponent -IncludeAllUsers

#>
    [CmdletBinding()]

    Param(
        [string[]]$ExcludePublisher = $null,
        [string[]]$IncludePublisher = $null,
        [string[]]$ExcludeDisplayName = $null,
        [string[]]$IncludeDisplayName = $null,
        [switch]$IncludeSystemComponent,
        [parameter(Mandatory = $false)]
        [Alias('AllUsers')]
        [switch]$IncludeAllUsers
    )
    
    $RegPath = @( 
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $RegPath64bit = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    If ( (Test-Path -Path $RegPath64bit) ) {
        $RegPath += $RegPath64bit
    }
    
    $Apps = ForEach ($Path in $RegPath) {
        $SelObjParams = @{
            'Property' = @(
                # Remove invalid control chars to prevent RMM from falsely reporting no output,
                # and to prevent weird behavior in other areas.
                @{n = 'DisplayName'; e = { ($_.DisplayName -replace '[^\u001F-\u007F]', '') } },
                @{n = 'DisplayVersion'; e = { ($_.DisplayVersion -replace '[^\u001F-\u007F]', '') } },
                @{n = 'Publisher'; e = { ($_.Publisher -replace '[^\u001F-\u007F]', '') } },
                'InstallDate',
                'InstallLocation',
                @{n = 'PathExists'; e = { If ($_.InstallLocation) { Test-Path $_.InstallLocation } else { $null } } },
                'UninstallString',
                'QuietUninstallString',
                'SystemComponent',
                'NoRemove',
                'NoRepair',
                'PSChildName',
                'PSPath',
                'PSParentPath'
                @{n = 'UserProfile'; e = { ($null) } } 
            )
        }
        Get-ItemProperty -Path $Path -ErrorAction 'SilentlyContinue' | Select-Object @SelObjParams
    }
    
    If ($IncludeAllUsers -eq $true) {
        $UserApps = (Get-UserApplication -ErrorAction $ErrorActionPreference)
        $Apps = $Apps + $UserApps
    }
        
    If ($null -ne $ExcludePublisher) {
        $RegExPattern = ( $ExcludePublisher | ForEach-Object { [regex]::Escape($_).Replace('\*', '.+') } ) -join '|'
        $Apps = $Apps | Where-Object { $_.Publisher -notmatch $RegExPattern }
    }
    
    If ($null -ne $IncludePublisher) {
        $RegExPattern = ( $IncludePublisher | ForEach-Object { [regex]::Escape($_).Replace('\*', '.+') } ) -join '|'
        $Apps = $Apps | Where-Object { $_.Publisher -match $RegExPattern }
    }
        
    If ($null -ne $ExcludeDisplayName) {
        $RegExPattern = ( $ExcludeDisplayName | ForEach-Object { [regex]::Escape($_).Replace('\*', '.+') } ) -join '|'
        $Apps = $Apps | Where-Object { $_.DisplayName -notmatch $RegExPattern }
    }
        
    If ($null -ne $IncludeDisplayName) {
        $RegExPattern = ( $IncludeDisplayName | ForEach-Object { [regex]::Escape($_).Replace('\*', '.+') } ) -join '|'
        $Apps = $Apps | Where-Object { $_.DisplayName -match $RegExPattern }
    }
    
    If ($IncludeSystemComponent -eq $true) {
        Write-Output $Apps | Where-Object { $null -ne $_.DisplayName -and '' -ne $_.DisplayName } 
    }
    Else {
        Write-Output $Apps | Where-Object { $null -ne $_.DisplayName -and '' -ne $_.DisplayName -and $_.SystemComponent -ne 1 }
    }          
}

#.EXAMPLE
# Get all apps and export to csv
# Get-InstalledApplication | Export-Csv

#.EXAMPLE
# Get all apps, Include system components and user-installed apps
# Get-InstalledApplication -IncludeSystemComponent -IncludeAllUsers
