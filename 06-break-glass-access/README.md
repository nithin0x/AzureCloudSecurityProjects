# Project 6: Break-Glass Access with Azure PIM

## Overview

This project sets up emergency break-glass procedures using Azure Privileged Identity Management (PIM). Instead of storing permanent administrative credentials, users receive time-limited, eligible role assignments requiring phishing-resistant MFA, business justification, and peer approval before activation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AZURE BREAK-GLASS ACCESS ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────────────┘

NORMAL OPERATIONS                          EMERGENCY / BREAK-GLASS
════════════════                           ═══════════════════════

┌──────────────────────────┐              ┌──────────────────────────────────────┐
│  Regular User Access     │              │  STEP 1: Activate PIM Role           │
│  • Entra ID login        │              │  ┌─────────────────────────────────┐ │
│  • Conditional Access    │              │  │ Security Admin opens Entra ID   │ │
│  • Standard RBAC roles   │              │  │ PIM → Activate "Global Admin"   │ │
└──────────────────────────┘              │  │ • Duration: 1 hour max          │ │
                                          │  │ • Justification: required       │ │
         ┌─────────────────────┐          │  │ • Approver: CISO notified       │ │
         │  AZURE PIM          │          │  └─────────────────────────────────┘ │
         │                     │          │                                       │
         │  • JIT Activation   │          │  STEP 2: MFA Re-authentication       │
         │  • Time-limited     │◀─────────│  ┌─────────────────────────────────┐ │
         │  • MFA required     │          │  │ PIM requires fresh MFA + PHISHRESISTANT │
         │  • Justification    │          │  │ hardware token (FIDO2/passkey)  │ │
         │  • Approval gates   │          │  └─────────────────────────────────┘ │
         │  • Audit trail      │          │                                       │
         └─────────────────────┘          │  STEP 3: Scoped Temporary Access     │
                  │                       │  ┌─────────────────────────────────┐ │
                  ▼                       │  │ Role active for approved time   │ │
         ┌─────────────────────┐          │  │ All actions logged to Sentinel  │ │
         │  SENTINEL ALERTS    │          │  │ Auto-deactivates at expiry      │ │
         │  • PIM activation   │          │  └─────────────────────────────────┘ │
         │  • Role changes     │          │                                       │
         │  • Admin actions    │          │  STEP 4: Automated Alerting          │
         │  → Security team    │          │  ┌─────────────────────────────────┐ │
         └─────────────────────┘          │  │ Sentinel alert → Teams/Email   │ │
                                          │  │ CISO + Security team notified  │ │
                                          │  │ Ticket auto-created (ITSM)     │ │
                                          │  └─────────────────────────────────┘ │
                                          └──────────────────────────────────────┘
```
## Implementation steps

### 1. Break-glass role definition (Bicep)

```bicep
// pim-settings.bicep
// Note: PIM is configured primarily through Entra ID (not ARM)
// This Bicep handles the RBAC foundations

param environment string
param breakGlassGroupObjectId string  // Entra ID security group for break-glass users

// Custom role for break-glass — scoped to specific actions only
resource breakGlassRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid('break-glass-role', subscription().subscriptionId)
  properties: {
    roleName: 'Break-Glass Emergency Operator'
    description: 'Emergency access role — activated only via PIM with CISO approval'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          // Read-all for investigation
          '*/read'
          // Emergency VM actions only
          'Microsoft.Compute/virtualMachines/start/action'
          'Microsoft.Compute/virtualMachines/restart/action'
          // Emergency networking
          'Microsoft.Network/networkSecurityGroups/securityRules/write'
          'Microsoft.Network/networkSecurityGroups/securityRules/delete'
          // Key Vault emergency access
          'Microsoft.KeyVault/vaults/secrets/read'
        ]
        notActions: [
          // NEVER allow data deletion via break-glass
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'
          '*/delete'
        ]
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      '/subscriptions/${subscription().subscriptionId}'
    ]
  }
}
```

### 2. PIM eligibility and activation settings (PowerShell)

```powershell
# Configure PIM settings for the break-glass role
# Requires: Az.Resources, Microsoft.Graph modules

Connect-AzAccount
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

# ── STEP 1: Create break-glass eligible role assignment ────────────────
$roleId = "GLOBAL-ADMIN-ROLE-ID"  # 62e90394-69f5-4237-9190-012177145e10
$breakGlassUserPrincipalName = "breakglass@yourcompany.com"

# Get user object ID
$user = Get-MgUser -Filter "userPrincipalName eq '$breakGlassUserPrincipalName'"

# Create ELIGIBLE (not active) role assignment via PIM
$pimParams = @{
    Action           = "adminAssign"
    PrincipalId      = $user.Id
    RoleDefinitionId = $roleId
    DirectoryScopeId = "/"
    Justification    = "Break-glass account — emergency access only"
    ScheduleInfo     = @{
        StartDateTime = Get-Date
        Expiration    = @{
            Type = "NoExpiration"  # Eligible assignment doesn't expire; activation is time-limited
        }
    }
}

New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest @pimParams

# ── STEP 2: Configure PIM activation settings (require approval + MFA) ─
$pimPolicyParams = @{
    ScopeId   = "/"
    ScopeType = "DirectoryRole"
    RoleDefinitionId = $roleId
    Rules = @(
        @{
            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
            Id            = "AuthenticationContext_EndUser_Assignment"
            IsEnabled     = $true
            ClaimValue    = "c1"  # Require phishing-resistant MFA (FIDO2/Passkey)
        },
        @{
            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
            Id            = "Approval_EndUser_Assignment"
            Setting       = @{
                IsApprovalRequired = $true  # Require CISO approval
                IsApprovalRequiredForExtension = $false
                IsRequestorJustificationRequired = $true
                ApprovalMode = "SingleStage"
                ApprovalStages = @(
                    @{
                        ApprovalStageTimeOutInDays = 1
                        EscalationTimeInMinutes    = 30
                        IsApproverJustificationRequired = $true
                        IsEscalationEnabled = $true
                        PrimaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                GroupId       = "CISO-GROUP-OBJECT-ID"  # CISO team group
                            }
                        )
                    }
                )
            }
        },
        @{
            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
            Id            = "Expiration_EndUser_Assignment"
            IsExpirationRequired = $true
            MaximumDuration      = "PT4H"  # Max 4 hours for break-glass activation
        }
    )
}
```

### 3. Emergency activation script

```bash
#!/bin/bash
# break-glass-activate.sh
# EMERGENCY SCRIPT — Only use when normal access is unavailable
# Every execution is logged to Sentinel

ROLE_NAME="Global Administrator"
JUSTIFICATION="EMERGENCY: Production outage — normal admin accounts locked out. Incident #$1"
DURATION_HOURS=2

if [ -z "$1" ]; then
  echo "ERROR: Must provide incident ticket number"
  echo "Usage: ./break-glass-activate.sh INC-2024-001"
  exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  ⚠️  BREAK-GLASS ACCESS ACTIVATION"
echo "  Incident: $1"
echo "  Role: $ROLE_NAME"
echo "  Duration: $DURATION_HOURS hours"
echo "  All actions will be logged and reviewed"
echo "═══════════════════════════════════════════════════════"

# Verify MFA is authenticated (interactive login forces re-auth)
az login --use-device-code

# Request PIM activation
az rest --method POST \
  --uri "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2022-04-01-preview" \
  --body "{
    \"properties\": {
      \"roleDefinitionId\": \"/providers/Microsoft.Authorization/roleDefinitions/62e90394-69f5-4237-9190-012177145e10\",
      \"principalId\": \"$(az ad signed-in-user show --query id -o tsv)\",
      \"requestType\": \"SelfActivate\",
      \"justification\": \"$JUSTIFICATION\",
      \"scheduleInfo\": {
        \"startDateTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"expiration\": {
          \"type\": \"AfterDuration\",
          \"duration\": \"PT${DURATION_HOURS}H\"
        }
      }
    }
  }"

echo ""
echo "✅ PIM activation requested. CISO has been notified for approval."
echo "⏱  Access will expire in $DURATION_HOURS hours automatically."
echo "📋 ALL ACTIONS ARE BEING LOGGED TO MICROSOFT SENTINEL"
echo ""
```

### 4. Sentinel detection queries

```kql
// Alert: PIM Privileged Role Activated
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName contains "Add eligible member"
    or OperationName contains "member added to role"
    or OperationName == "Activate eligible assignment"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Access Administrator"
  )
| project TimeGenerated, OperationName, RoleName, ActorUPN, Result
| order by TimeGenerated desc
```

```kql
// Alert: Actions Taken During Break-Glass Session
// (Tag break-glass users and audit ALL their actions)
let breakGlassUsers = dynamic(["breakglass@yourcompany.com"]);
AzureActivity
| where TimeGenerated > ago(24h)
| where Caller in~ (breakGlassUsers)
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceId, Properties
| order by TimeGenerated desc
```

## Break-glass security procedures

```
BREAK-GLASS ACCESS PROCEDURES
══════════════════════════════

Break-Glass Account Setup
  ☐ Create dedicated break-glass accounts (not tied to any person)
  ☐ Accounts excluded from all Conditional Access policies
  ☐ Accounts NOT in any groups (direct role assignment only)
  ☐ Use cloud-only accounts (not synced from on-premises AD)
  ☐ Store credentials in physical safe (offline) + Azure Key Vault (HSM-backed)
  ☐ Configure FIDO2 hardware keys as the ONLY authentication method
  ☐ Test break-glass procedures quarterly

PIM Configuration
  ☐ All privileged roles eligible (not permanently assigned) via PIM
  ☐ Global Admin role requires CISO team approval
  ☐ Maximum activation duration: 4 hours
  ☐ Justification required for all activations
  ☐ MFA required on every activation (even if already authenticated)
  ☐ Activation alerts sent to Security team + CISO immediately

Monitoring
  ☐ Sentinel alert: PIM privileged role activated
  ☐ Sentinel alert: Break-glass account sign-in
  ☐ Sentinel alert: Actions taken by break-glass account
  ☐ PIM access reviews — monthly for Global Admin
  ☐ Access review results reported to Security committee

Post-Emergency Procedures
  ☐ Immediately deactivate PIM role after emergency resolved
  ☐ Document all actions taken during break-glass session
  ☐ Rotate break-glass credentials after use
  ☐ Conduct post-incident review within 48 hours
  ☐ Update incident runbook based on lessons learned
```

## Key security capabilities of Azure PIM

1. Identity-based elevation: PIM elevates an existing Entra ID account just in time rather than relying on static accounts or permanent credential stores.
2. Built-in approval chains: Entra ID includes native approval routing without requiring external notification infrastructure.
3. Automatic expiration: PIM assignments expire on a configured timer, preventing forgotten administrative sessions.
4. Phishing-resistant enforcement: Activation policies can require FIDO2 keys specifically when requesting elevated rights.
5. Unified directory coverage: One PIM policy covers Azure subscription roles, Entra ID directory roles, and Microsoft 365 services.
6. Recurring access reviews: Built-in attestation campaigns audit privileged access eligibility on a schedule.
