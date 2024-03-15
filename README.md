# Preqrequisite-for-Migration-from-Azure-Automation-Update-Management-to-Azure-Update-Manager
This Powershell script is designed to carry out the prerequisites required for migration of machines and update schedules from Azure Automation Update Management to Azure Update Manager.

### DESCRIPTION
This script will do the following:

1. Retrieve all machines onboarded to Azure Automation Update Management under this automation account from linked log analytics workspace.
2. Update the Az.Modules for the automation account.
3. Create user managed identity in the same subscription and resource group as the automation account.
4. Associate the user managed identity to the automation account.
5. Assign required roles to the user managed identity created.

The executor of the script should have Microsoft.Authorization/roleAssignments/write action such as Role Based Access Control Administrator on the scopes on which access will be granted to user managed identity. 
The script will register the automation subscription, subscriptions to which machines belong and subscriptions in dynamic azure queries to Microsoft.Maintenance and hence executor of the script should have Contributor/Owner access to all those subscriptions.

### PARAMETER AutomationAccountResourceId
        Mandatory. Automation Account Resource Id.
    
### EXAMPLE
        MigrationPrerequisites -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"

### OUTPUTS
        The user managed identity with required role assignments.