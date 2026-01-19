# 1. Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 2. Create the Arena Forest (This will prompt for a DSRM password)
# Note: This will automatically reboot the server!
Install-ADDSForest `
    -DomainName "arena.local" `
    -DomainNetbiosName "ARENA" `
    -InstallDns `
    -Force