# Active Directory User Audit and Update Script
# This script provides two main functions:
# 1. Export all AD users and their attributes to a CSV file
# 2. Import a modified CSV file to update user attributes including UPN and proxyAddresses

# Import the Active Directory module
Import-Module ActiveDirectory

# Function to export all AD users and their attributes to a CSV file
function Export-ADUsersToCsv {
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )

    Write-Host "Exporting AD users to CSV file: $OutputPath" -ForegroundColor Green

    # Get all users from Active Directory
    # Feel free to modify the properties list based on your requirements
    $users = Get-ADUser -Filter * -Properties * | Select-Object `
        SamAccountName, 
        UserPrincipalName, 
        DisplayName, 
        GivenName, 
        Surname, 
        Title, 
        Department, 
        Company, 
        Office, 
        StreetAddress, 
        City, 
        State, 
        PostalCode, 
        Country, 
        EmailAddress, 
        OfficePhone, 
        MobilePhone, 
        Description, 
        EmployeeID, 
        EmployeeNumber, 
        Manager, 
        Enabled, 
        PasswordLastSet,
        @{Name="proxyAddresses"; Expression={$_.proxyAddresses -join ";"}},
        LastLogonDate, 
        AccountExpirationDate, 
        DistinguishedName

    # Export users to CSV
    $users | Export-Csv -Path $OutputPath -NoTypeInformation

    Write-Host "Successfully exported $($users.Count) users to $OutputPath" -ForegroundColor Green
}

# Function to import CSV file and update user attributes
function Import-ADUsersFromCsv {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InputPath
    )

    Write-Host "Importing and updating users from CSV file: $InputPath" -ForegroundColor Green

    # Ask how to handle proxyAddresses
    $proxyAddressMode = Read-Host "How should proxyAddresses be processed? 
    1. Replace existing proxyAddresses
    2. Add to existing proxyAddresses (keep both new and old)
    Enter your choice (1 or 2)"

    # Import the CSV file
    $users = Import-Csv -Path $InputPath

    # Counter for successful updates
    $successCount = 0

    # Process each user in the CSV
    foreach ($user in $users) {
        try {
            # Find the user in AD
            $adUser = Get-ADUser -Identity $user.SamAccountName -Properties proxyAddresses -ErrorAction Stop

            # Create a hashtable of properties to update
            $updateParams = @{}

            # Add properties to update based on CSV columns
            # Only include properties that are not null or empty
            if ($user.UserPrincipalName) { $updateParams["UserPrincipalName"] = $user.UserPrincipalName }
            if ($user.DisplayName) { $updateParams["DisplayName"] = $user.DisplayName }
            if ($user.GivenName) { $updateParams["GivenName"] = $user.GivenName }
            if ($user.Surname) { $updateParams["Surname"] = $user.Surname }
            if ($user.Title) { $updateParams["Title"] = $user.Title }
            if ($user.Department) { $updateParams["Department"] = $user.Department }
            if ($user.Company) { $updateParams["Company"] = $user.Company }
            if ($user.Office) { $updateParams["Office"] = $user.Office }
            if ($user.StreetAddress) { $updateParams["StreetAddress"] = $user.StreetAddress }
            if ($user.City) { $updateParams["City"] = $user.City }
            if ($user.State) { $updateParams["State"] = $user.State }
            if ($user.PostalCode) { $updateParams["PostalCode"] = $user.PostalCode }
            if ($user.Country) { $updateParams["Country"] = $user.Country }
            if ($user.EmailAddress) { $updateParams["EmailAddress"] = $user.EmailAddress }
            if ($user.OfficePhone) { $updateParams["OfficePhone"] = $user.OfficePhone }
            if ($user.MobilePhone) { $updateParams["MobilePhone"] = $user.MobilePhone }
            if ($user.Description) { $updateParams["Description"] = $user.Description }
            if ($user.EmployeeID) { $updateParams["EmployeeID"] = $user.EmployeeID }
            if ($user.EmployeeNumber) { $updateParams["EmployeeNumber"] = $user.EmployeeNumber }
            if ($user.Manager) { $updateParams["Manager"] = $user.Manager }

            # Handle proxyAddresses attribute specially since it's multi-valued
            if ($user.proxyAddresses) {
                # Split the semicolon-separated values into an array
                $proxyAddressValues = $user.proxyAddresses -split ";"
                
                # Get current proxyAddresses
                $currentProxyAddresses = $adUser.proxyAddresses
                
                if ($proxyAddressMode -eq "1") {
                    # Replace mode - Clear existing values first
                    if ($currentProxyAddresses -and $currentProxyAddresses.Count -gt 0) {
                        foreach ($value in $currentProxyAddresses) {
                            Set-ADUser -Identity $adUser.DistinguishedName -Remove @{proxyAddresses = $value}
                        }
                    }
                    
                    # Add all values from CSV
                    foreach ($value in $proxyAddressValues) {
                        if ($value -and $value.Trim() -ne "") {
                            Set-ADUser -Identity $adUser.DistinguishedName -Add @{proxyAddresses = $value.Trim()}
                        }
                    }
                    
                    Write-Host "  Replaced proxyAddresses values for $($user.SamAccountName)" -ForegroundColor Cyan
                }
                else {
                    # Add mode - Only add new values
                    foreach ($value in $proxyAddressValues) {
                        if ($value -and $value.Trim() -ne "" -and $currentProxyAddresses -notcontains $value.Trim()) {
                            Set-ADUser -Identity $adUser.DistinguishedName -Add @{proxyAddresses = $value.Trim()}
                            Write-Host "  Added '$value' to proxyAddresses for $($user.SamAccountName)" -ForegroundColor Cyan
                        }
                    }
                }
                
                # Remove proxyAddresses from updateParams since we've handled it separately
                if ($updateParams.ContainsKey("ProxyAddresses")) {
                    $updateParams.Remove("ProxyAddresses")
                }
            }

            # Only update if there are changes to make
            if ($updateParams.Count -gt 0) {
                # Update the user
                Set-ADUser -Identity $adUser.DistinguishedName @updateParams
                $successCount++
                Write-Host "Updated user attributes for: $($user.SamAccountName)" -ForegroundColor Green
            }
            elseif ($user.proxyAddresses) {
                # If we only updated proxyAddresses, still count as success
                $successCount++
                Write-Host "Updated proxyAddresses for user: $($user.SamAccountName)" -ForegroundColor Green
            }
            else {
                Write-Host "No changes for user: $($user.SamAccountName)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Error updating user $($user.SamAccountName): $_" -ForegroundColor Red
        }
    }

    Write-Host "Update complete. Successfully updated $successCount users." -ForegroundColor Green
}

# Main script execution
$scriptAction = Read-Host "Would you like to 'Export' AD users to CSV or 'Import' and update from CSV? (Export/Import)"

if ($scriptAction -eq "Export") {
    $outputPath = Read-Host "Enter the path for the output CSV file (e.g., C:\Temp\ADUsers.csv)"
    Export-ADUsersToCsv -OutputPath $outputPath
}
elseif ($scriptAction -eq "Import") {
    $inputPath = Read-Host "Enter the path to the CSV file to import (e.g., C:\Temp\ADUsers_Updated.csv)"
    Import-ADUsersFromCsv -InputPath $inputPath
}
else {
    Write-Host "Invalid option. Please run the script again and choose 'Export' or 'Import'." -ForegroundColor Red
}