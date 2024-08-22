# Service Principal Permissions

The minimum permissions and roles that must be assigned to the service principal are listed in the table below.

| Product                 | API Permissions                                 | Role          |
| ----------------------- | ----------------------------------------------- | ------------- |
| Entra ID                | Directory.Read.All, GroupMember.Read.All,       |               |
|                         | Organization.Read.All, Policy.Read.All,         |               |
|                         | RoleManagement.Read.Directory, User.Read.All    |               |
|                         | PrivilegedEligibilitySchedule.Read.AzureADGroup |               |
|                         | PrivilegedAccess.Read.AzureADGroup              |               |
|                         | RoleManagementPolicy.Read.AzureADGroup          |               |
| Defender for Office 365 | Exchange.ManageAsApp                            | Global Reader |
| Exchange Online         | Exchange.ManageAsApp                            | Global Reader |
| Power Platform          | (see below)                                     |               |
| SharePoint Online       | Sites.FullControl.All, Directory.Read.All       |               |
| Microsoft Teams         |                                                 | Global Reader |
