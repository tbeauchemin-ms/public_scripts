// Deploys an Azure Automation Account (using Azure Verified Module), a Runbook that pulls the Test-BlobContainerBackups script from GitHub, and a daily schedule.

@description('Name of the Automation Account')
param automationAccountName string

@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the Automation Runbook')
param runbookName string = 'Test-BlobContainerBackups'

@description('GitHub raw URL to the PowerShell script')
param scriptGitHubRawUrl string

@description('Daily schedule start time in UTC (e.g. 2024-05-28T00:00:00Z)')
param scheduleStartTime string

@description('Tags for resources')
param tags object = {}

module automationAccount 'br/public:automationaccount:3.1.0' = {
  name: 'automationAccount'
  params: {
    name: automationAccountName
    location: location
    identity: {
      type: 'SystemAssigned'
    }
    tags: tags
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2023-05-15-preview' = {
  name: '${automationAccount.name}/${runbookName}'
  location: location
  properties: {
    runbookType: 'PowerShell'
    logProgress: true
    logVerbose: true
    description: 'Checks if Blob containers in specified Storage Accounts are protected by Azure Backup.'
    publishContentLink: {
      uri: scriptGitHubRawUrl
      version: '1.0.0.0'
    }
  }
  dependsOn: [
    automationAccount
  ]
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-05-15-preview' = {
  name: '${automationAccount.name}/DailyBlobBackupCheck'
  location: location
  properties: {
    description: 'Daily schedule for Test-BlobContainerBackups runbook'
    startTime: scheduleStartTime
    frequency: 'Day'
    interval: 1
    timeZone: 'UTC'
  }
  dependsOn: [
    automationAccount
  ]
}

resource job 'Microsoft.Automation/automationAccounts/jobSchedules@2023-05-15-preview' = {
  name: guid(automationAccount.name, runbook.name, schedule.name)
  properties: {
    runbook: {
      name: runbookName
    }
    schedule: {
      name: schedule.name
    }
  }
  dependsOn: [
    runbook
    schedule
  ]
}
