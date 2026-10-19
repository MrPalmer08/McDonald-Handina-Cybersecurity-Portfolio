<#
PowerShell: Example AD population script (lab only)
Requirements: Run on a Windows Server with ActiveDirectory module installed (RSAT). Run in an isolated lab. This script creates test users and assigns them to a group.
#>

Param(
    [int]$Count = 100
)

Import-Module ActiveDirectory

# Safety check: ensure domain name contains 'lab' or 'letsdefend' to reduce risk
$domain = (Get-ADDomain).DNSRoot
if ($domain -notlike "*lab*" -and $domain -notlike "*letsdefend*") {
    Write-Error "Refusing to run: domain name does not look like a lab environment ($domain). Aborting."
    exit 1
}

$baseOU = "OU=TestUsers,DC=letsdefend,DC=local"
# Create OU if it doesn't exist
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'TestUsers'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "TestUsers" -Path "DC=letsdefend,DC=local"
}

$group = "CN=LabUsers,$baseOU"
if (-not (Get-ADGroup -Filter "Name -eq 'LabUsers'" -SearchBase $baseOU -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "LabUsers" -GroupScope Global -Path $baseOU -Description "Lab user group"
}

for ($i = 1; $i -le $Count; $i++) {
    $sam = "labuser$i"
    $name = "Lab User $i"
    $pwd = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
    New-ADUser -Name $name -SamAccountName $sam -AccountPassword $pwd -Enabled $true -Path $baseOU -ChangePasswordAtLogon $false
    Add-ADGroupMember -Identity "LabUsers" -Members $sam
}

Write-Output "Created $Count lab users in $baseOU and added to LabUsers group."
