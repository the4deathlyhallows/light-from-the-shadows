targetScope = 'resourceGroup'

@description('Azure region for Microsoft Sentinel resources')
param location string = resourceGroup().location

@description('Workspace name hosting Sentinel')
param workspaceName string

@description('Resource id of the Log Analytics workspace')
param workspaceResourceId string

@description('Enable sample rule deployment')
param deploySampleRules bool = true

module scheduledRuleRoleAssignment './modules/scheduledRule.bicep' = if (deploySampleRules) {
  name: 'deploy-azi-0001'
  params: {
    workspaceResourceId: workspaceResourceId
    alertRuleName: 'AZI-0001'
    displayName: 'AZI-0001 Privileged role assignment created or deleted'
    description: 'Detects writes or deletes to Azure role assignments.'
    severity: 'High'
    query: '''
let timeframe = 1h;
AzureActivity
| where TimeGenerated >= ago(timeframe)
| where CategoryValue == "Administrative"
| where OperationNameValue has_any ("Microsoft.Authorization/roleAssignments/write","Microsoft.Authorization/roleAssignments/delete")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, ResourceGroup, ResourceId, SubscriptionId
'''
    tactics: [
      'PrivilegeEscalation'
    ]
    techniques: [
      'T1098'
    ]
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
  }
}
