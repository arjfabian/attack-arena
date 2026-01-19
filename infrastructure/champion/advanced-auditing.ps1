# Enable Directory Service Changes (Success)
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# Enable Account Management (Success/Failure)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Force the policy update
gpupdate /force