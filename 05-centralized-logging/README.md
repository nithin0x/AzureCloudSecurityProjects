# Project 5: Centralized Logging with Microsoft Sentinel & Azure Monitor

## Overview

This project builds a centralized security logging and SIEM pipeline on Azure using Microsoft Sentinel, Log Analytics workspaces, and Azure Monitor. It routes directory logs, subscription activity, network telemetry, and workload protection alerts into a central workspace with automated incident response rules.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AZURE CENTRALIZED LOGGING ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────────────────────┘

  Data Sources                        Collection                    SIEM / Analytics
  ────────────                         ──────────                    ────────────────
  ┌───────────────┐                  ┌──────────────────────┐       ┌──────────────┐
  │ Entra ID Logs │───────────┐      │                      │       │  Microsoft   │
  │ (Sign-ins,    │           │      │  Log Analytics       │──────▶│  Sentinel    │
  │  Audit logs)  │           ├─────▶│  Workspace (Central) │       │              │
  │───────────────┘           │      │                      │       │  • Analytics │
  ┌───────────────┐           │      │  Retention: 90 days  │       │    Rules     │
  │ Azure Activity│───────────┤      │  Archive:  7 years   │       │  • Incidents │
  │ Logs          │           │      └──────────────────────┘       │  • Hunting   │
  └───────────────┘           │                 ▲                   │  • Workbooks │
  ┌───────────────┐           │                 │                   └──────────────┘
  │ Azure Firewall│───────────┤      ┌──────────┴───────────┐
  │ Logs          │           │      │  Data Connectors:    │
  └───────────────┘           ├─────▶│  • Entra ID          │
  ┌───────────────┐           │      │  • Azure Activity    │
  │ Defender for  │───────────┤      │  • Defender for Cloud│
  │ Cloud Alerts  │           │      │  • Microsoft 365     │
  └───────────────┘           │      │  • GitHub / ADO      │
  ┌───────────────┐           │      │  • Azure Firewall    │
  │ NSG Flow Logs │───────────┤      │  • CEF/Syslog        │
  └───────────────┘           │      └──────────────────────┘
  ┌───────────────┐           │
  │ VM / AKS Logs │───────────┘
  └───────────────┘
```
## Implementation steps

### 1. Sentinel workspace configuration (Bicep)

```bicep
// sentinel-workspace.bicep

param location string = resourceGroup().location
param environment string

var tags = {
  Environment: environment
  Purpose: 'SecuritySIEM'
  ManagedBy: 'Bicep'
}

// ─────────────────────────────────────────────────────
// LOG ANALYTICS WORKSPACE (Central SIEM storage)
// ─────────────────────────────────────────────────────
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-sentinel-${environment}'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'  // Pay-per-GB ingestion pricing
    }
    retentionInDays: 90      // 90 days hot retention
    features: {
      searchVersion: 1
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: 100  // Daily cap to prevent cost surprises
    }
  }
}

// ─────────────────────────────────────────────────────
// MICROSOFT SENTINEL (SIEM on top of Log Analytics)
// ─────────────────────────────────────────────────────
resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2023-02-01-preview' = {
  name: 'default'
  scope: logAnalyticsWorkspace
  properties: {}
}

// ─────────────────────────────────────────────────────
// DATA CONNECTORS
// ─────────────────────────────────────────────────────

// Entra ID (Azure AD) — Sign-in + Audit logs
resource entraIdConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: guid('AzureActiveDirectory', logAnalyticsWorkspace.id)
  kind: 'AzureActiveDirectory'
  scope: logAnalyticsWorkspace
  properties: {
    tenantId: tenant().tenantId
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
  }
}

// Azure Activity Log
resource activityLogConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: guid('AzureActivity', logAnalyticsWorkspace.id)
  kind: 'AzureActivity'
  scope: logAnalyticsWorkspace
  properties: {
    linkedResourceId: '/subscriptions/${subscription().subscriptionId}/providers/microsoft.insights/eventtypes/management'
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
  }
}

// Microsoft Defender for Cloud
resource defenderConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: guid('AzureSecurityCenter', logAnalyticsWorkspace.id)
  kind: 'AzureSecurityCenter'
  scope: logAnalyticsWorkspace
  properties: {
    subscriptionId: subscription().subscriptionId
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
  }
}

// ─────────────────────────────────────────────────────
// DIAGNOSTIC SETTINGS — Route Azure Activity Log
// ─────────────────────────────────────────────────────
resource activityLogDiagnosticSetting 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-activity-to-sentinel'
  scope: subscription()
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'Administrative'
        enabled: true
        retentionPolicy: { days: 90, enabled: true }
      }
      {
        category: 'Security'
        enabled: true
        retentionPolicy: { days: 90, enabled: true }
      }
      {
        category: 'Policy'
        enabled: true
        retentionPolicy: { days: 90, enabled: true }
      }
      {
        category: 'Alert'
        enabled: true
        retentionPolicy: { days: 90, enabled: true }
      }
    ]
  }
}

// ─────────────────────────────────────────────────────
// SENTINEL ANALYTICS RULES (Alert rules)
// ─────────────────────────────────────────────────────

// Rule: Detect impossible travel
resource impossibleTravelRule 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('impossible-travel-rule')
  kind: 'Scheduled'
  scope: logAnalyticsWorkspace
  properties: {
    displayName: 'Impossible Travel — Suspicious Sign-in Locations'
    description: 'Detects sign-ins from geographically impossible locations within a short time window'
    severity: 'High'
    enabled: true
    query: '''
      let timeframe = 6h;
      let threshold_km = 500;
      SigninLogs
      | where TimeGenerated > ago(timeframe)
      | where ResultType == "0"
      | extend City = tostring(LocationDetails.city),
               CountryOrRegion = tostring(LocationDetails.countryOrRegion),
               Latitude = todouble(LocationDetails.geoCoordinates.latitude),
               Longitude = todouble(LocationDetails.geoCoordinates.longitude)
      | where isnotempty(Latitude) and isnotempty(Longitude)
      | sort by UserPrincipalName, TimeGenerated asc
      | extend PrevTime = prev(TimeGenerated),
               PrevLat = prev(Latitude),
               PrevLon = prev(Longitude),
               PrevCity = prev(City),
               PrevUser = prev(UserPrincipalName)
      | where UserPrincipalName == PrevUser
      | extend TimeDiffHours = datetime_diff('hour', TimeGenerated, PrevTime)
      | extend DistanceKm = geo_distance_2points(Longitude, Latitude, PrevLon, PrevLat) / 1000
      | where DistanceKm > threshold_km and TimeDiffHours < 2
      | project TimeGenerated, UserPrincipalName, City, PrevCity,
                DistanceKm = round(DistanceKm, 0),
                TimeDiffHours, IPAddress
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT6H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['InitialAccess', 'Persistence']
    techniques: ['T1078']
  }
}

// Rule: Privilege Escalation Detection
resource privilegeEscalationRule 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('privilege-escalation-rule')
  kind: 'Scheduled'
  scope: logAnalyticsWorkspace
  properties: {
    displayName: 'Privilege Escalation — Global Admin Role Assignment'
    description: 'Alerts when a user is added to Global Administrator or Security Administrator role'
    severity: 'High'
    enabled: true
    query: '''
      AuditLogs
      | where TimeGenerated > ago(1h)
      | where OperationName == "Add member to role"
      | extend RoleName = tostring(TargetResources[0].displayName),
               AssignedUser = tostring(TargetResources[1].userPrincipalName),
               InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
      | where RoleName in ("Global Administrator", "Security Administrator",
                            "Privileged Role Administrator", "User Access Administrator")
      | project TimeGenerated, RoleName, AssignedUser, InitiatedBy, OperationName, Result
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['PrivilegeEscalation']
    techniques: ['T1078.004']
  }
}
```

### 2. Detection queries (KQL)

```kql
// ── 1. Failed Sign-Ins Brute Force Detection ────────────
// Detect accounts with >10 failed sign-ins in 5 minutes
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"  // Failed sign-ins
| summarize FailedAttempts = count(), IPList = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

```kql
// ── 2. Suspicious Azure Resource Deletions ──────────────
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "delete" or OperationNameValue has "remove"
| where ActivityStatusValue == "Success"
| where Caller !endswith "@microsoft.com"
| project TimeGenerated, Caller, OperationNameValue, ResourceId, SubscriptionId
| order by TimeGenerated desc
```

```kql
// ── 3. Service Principal Creating Service Principals ────
// High-risk: lateral movement via SPN creation
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add application"
| where InitiatedBy.app.displayName != ""  // Initiated by a service principal
| project TimeGenerated,
          InitiatingApp = tostring(InitiatedBy.app.displayName),
          NewApp = tostring(TargetResources[0].displayName),
          Result
```

```kql
// ── 4. Key Vault Secrets Mass Download ──────────────────
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| summarize SecretsAccessed = count() by CallerIPAddress, identity_claim_oid_g, bin(TimeGenerated, 5m)
| where SecretsAccessed > 20  // >20 secrets accessed in 5 mins = suspicious
| order by SecretsAccessed desc
```

```kql
// ── 5. Azure Firewall — Top Denied Destinations ─────────
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "AzureFirewallNetworkRule"
| where msg_s has "DENY"
| parse msg_s with * "from " SourceIP ":" SourcePort " to " DestIP ":" DestPort "." *
| summarize DeniedCount = count() by DestIP, DestPort
| order by DeniedCount desc
| take 20
```

```kql
// ── 6. Defender for Cloud — High Severity Alerts ────────
SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertSeverity == "High"
| where Status == "New"
| project TimeGenerated, AlertName, Description, ResourceId,
          RemediationSteps, Tactics = tostring(Tactics)
| order by TimeGenerated desc
```

### 3. Incident response automation (Logic App playbook)

```json
// Auto-block user on high-risk sign-in detection
// Triggered by Sentinel alert rule: "High Risk Sign-in Detected"
{
  "definition": {
    "triggers": {
      "Microsoft_Sentinel_alert": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "body": { "callback_url": "@{listCallbackUrl()}" },
          "path": "/subscribe"
        }
      }
    },
    "actions": {
      "Get_incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "method": "GET",
          "path": "/Incidents/subscriptions/@{encodeURIComponent(triggerBody()?['WorkspaceSubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['WorkspaceResourceGroup'])}/workspaces/@{encodeURIComponent(triggerBody()?['WorkspaceId'])}/incidents/@{encodeURIComponent(triggerBody()?['SystemAlertId'])}"
        }
      },
      "Revoke_user_sessions": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuread']['connectionId']" } },
          "method": "POST",
          "path": "/v1.0/users/@{body('Get_incident')?['properties']?['relatedEntities']?[0]?['properties']?['userPrincipalName']}/revokeSignInSessions"
        }
      },
      "Add_comment_to_incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "method": "POST",
          "body": {
            "message": "🔒 AUTOMATED RESPONSE: User sessions revoked due to high-risk sign-in detection. Timestamp: @{utcNow()}"
          }
        }
      }
    }
  }
}
```

## Security checklist

```
MICROSOFT SENTINEL DEPLOYMENT CHECKLIST
════════════════════════════════════════

Data Collection
  ☐ Entra ID sign-in and audit logs connected
  ☐ Azure Activity Log connected (all subscriptions)
  ☐ Microsoft Defender for Cloud alerts connected
  ☐ NSG Flow Logs → Traffic Analytics
  ☐ Azure Firewall logs connected
  ☐ Key Vault diagnostic logs enabled
  ☐ AKS audit logs connected (if applicable)
  ☐ Microsoft 365 / Exchange logs connected (if applicable)

Analytics Rules
  ☐ Impossible travel detection enabled
  ☐ Brute force detection (sign-ins + SSH + RDP)
  ☐ Privileged role changes alert
  ☐ Service principal anomalous behavior
  ☐ Key Vault mass secret access detection
  ☐ Azure resource mass deletion alert
  ☐ Credential exposure (Defender for DevOps)

Incident Response Automation
  ☐ Playbook: Auto-revoke high-risk user sessions
  ☐ Playbook: Notify Security team via Teams/email
  ☐ Playbook: Isolate compromised VM (via Defender)
  ☐ Playbook: Block IP in Azure Firewall

Retention & Compliance
  ☐ Hot tier retention: 90 days minimum
  ☐ Cold archive tier: 1–7 years (regulatory)
  ☐ Workspace daily cap configured
  ☐ Workspace access restricted to Security team
  ☐ Customer-managed keys (CMK) for workspace encryption
```
