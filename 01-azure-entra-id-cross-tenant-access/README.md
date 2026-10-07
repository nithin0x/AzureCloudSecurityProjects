# Project 1: Entra ID Cross-Tenant Access & Managed Identity

## Overview

This project sets up cross-tenant access and passwordless authentication across Azure subscriptions using Microsoft Entra ID. It covers B2B collaboration, Managed Identities, custom Azure RBAC roles, and Workload Identity Federation for external pipelines.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AZURE ENTRA ID (TENANT)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌────────────────────────────┐      ┌────────────────────────────┐        │
│  │   SECURITY SUBSCRIPTION    │      │    WORKLOAD SUBSCRIPTION   │        │
│  │   (Tenant: corp.onmicro..) │      │   (Tenant: partner.com)    │        │
│  │                            │      │                            │        │
│  │  ┌──────────────────────┐  │      │  ┌──────────────────────┐  │        │
│  │  │  Managed Identity /  │  │      │  │  Azure RBAC Role      │  │        │
│  │  │  Service Principal   │──┼──────┼─▶│  Assignment          │  │        │
│  │  │  "SecurityAdmin"     │  │ B2B  │  │  "SecurityReader"    │  │        │
│  │  │                      │  │Cross │  │                      │  │        │
│  │  │  ┌────────────────┐  │  │Tenant│  │  ┌────────────────┐  │  │        │
│  │  │  │ Federated      │  │  │      │  │  │ Trust Settings │  │  │        │
│  │  │  │ Credential /   │  │  │      │  │  │                │  │  │        │
│  │  │  │ OIDC Token     │  │  │      │  │  │ Condition:     │  │  │        │
│  │  │  └────────────────┘  │  │      │  │  │ MFA Claim      │  │  │        │
│  │  └──────────────────────┘  │      │  │  │ Compliant Devs │  │  │        │
│  │                            │      │  │  └────────────────┘  │  │        │
│  │  └────────────────────────────┘      │  └──────────────────────┘  │        │
│  │                                      └────────────────────────────┘        │
│  │  ┌─────────────────────────────────────────────────────────────┐            │
│  │  │              AZURE POLICY + CONDITIONAL ACCESS              │            │
│  │  │  • Require MFA for all admin roles                          │            │
│  │  │  • Block legacy authentication                              │            │
│  │  │  • Require compliant/Entra-joined devices                   │            │
│  │  │  • PIM-enforced JIT for privileged roles                    │            │
│  │  └─────────────────────────────────────────────────────────────┘            │
│  └─────────────────────────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────────────────┘
```
## Implementation steps

### 1. Managed Identity setup

```bicep
// managed-identity.bicep
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-security-admin-${environment}'
  location: location
  tags: {
    Environment: environment
    Purpose: 'SecurityAdministration'
    CostCenter: 'Security'
  }
}

// Assign the managed identity the Security Reader role on the workload subscription
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().subscriptionId, managedIdentity.id, securityReaderRoleId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', securityReaderRoleId)
    principalId: managedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}
```

### 2. Custom RBAC role

```json
{
  "Name": "Security Audit Reader",
  "Description": "Can read security configurations and audit logs without write access",
  "IsCustom": true,
  "Actions": [
    "Microsoft.Security/*/read",
    "Microsoft.Authorization/*/read",
    "Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Compute/virtualMachines/read"
  ],
  "NotActions": [
    "Microsoft.Security/*/write",
    "Microsoft.Security/*/delete"
  ],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/{workload-subscription-id}"
  ]
}
```

```bash
# Create the custom role
az role definition create --role-definition @security-audit-reader.json

# Assign to the Managed Identity
az role assignment create \
  --assignee-object-id $(az identity show --name id-security-admin-prod \
      --resource-group rg-security \
      --query principalId -o tsv) \
  --assignee-principal-type ServicePrincipal \
  --role "Security Audit Reader" \
  --scope /subscriptions/<workload-subscription-id>
```

### 3. Cross-tenant B2B access

```bash
# Invite a guest user from a partner tenant
az ad user invite \
  --invited-user-email-address "securityauditor@partner.com" \
  --invite-redirect-url "https://portal.azure.com" \
  --display-name "Partner Security Auditor"

# Assign them a role in your subscription
GUEST_OBJECT_ID=$(az ad user show --id "securityauditor@partner.com" --query id -o tsv)

az role assignment create \
  --assignee "$GUEST_OBJECT_ID" \
  --role "Security Reader" \
  --scope /subscriptions/<your-subscription-id>
```

### 4. Conditional Access policies

```json
{
  "displayName": "Require MFA for Security Admin Role",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]
    },
    "applications": {
      "includeApplications": ["All"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice"]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": 1,
      "type": "hours"
    }
  }
}
```

### 5. Workload identity federation

```bash
# Register your GitHub Actions / Azure DevOps pipeline as a federated identity
az ad app create --display-name "GitHubActions-SecurityScanner"

APP_ID=$(az ad app list --display-name "GitHubActions-SecurityScanner" --query "[0].appId" -o tsv)

# Create a federated credential for GitHub Actions
az ad app federated-credential create \
  --id $APP_ID \
  --parameters '{
    "name": "github-actions-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:your-org/your-repo:ref:refs/heads/main",
    "description": "GitHub Actions OIDC federation",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

## Security hardening checklist

```
ENTRA ID SECURITY HARDENING
════════════════════════════

Identity Foundations
  ☐ Enable Security Defaults or custom Conditional Access policies
  ☐ Block legacy authentication protocols (SMTP, POP3, IMAP, Basic Auth)
  ☐ Enable Microsoft Entra ID Protection risk-based Conditional Access
  ☐ Configure Self-Service Password Reset (SSPR) with MFA
  ☐ Enable Continuous Access Evaluation (CAE)

Privileged Access
  ☐ Enable Privileged Identity Management (PIM) for all privileged roles
  ☐ Require MFA activation for all PIM-eligible roles
  ☐ Set justification + approval for Global Admin, Security Admin roles
  ☐ Configure role activation alerts to Security team
  ☐ Review PIM access reviews quarterly

Service Principals & Managed Identities
  ☐ Prefer System-Assigned Managed Identity over service principal secrets
  ☐ For service principals, use certificate credentials (not passwords)
  ☐ Use Workload Identity Federation (OIDC) for CI/CD pipelines
  ☐ Rotate service principal certificates every 90 days
  ☐ Monitor service principal sign-ins via Entra ID logs

RBAC Governance
  ☐ Remove Owner/Contributor assignments at subscription scope
  ☐ Use custom roles for least-privilege access patterns
  ☐ Enable Azure RBAC for Kubernetes (AKS) clusters
  ☐ Quarterly access reviews using Entra ID Access Reviews
  ☐ Deny assignments at Management Group level for security guardrails
```

## Detection: monitoring cross-tenant access

```kql
// Azure Monitor / Sentinel KQL — Detect suspicious cross-tenant sign-ins
SigninLogs
| where TimeGenerated > ago(24h)
| where HomeTenantId != ResourceTenantId  // Cross-tenant access
| where ResultType == "0"  // Successful sign-ins
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, HomeTenantId, ResourceTenantId,
          AppDisplayName, IPAddress, Location, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

```kql
// Detect privilege escalation via role assignment changes
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties contains "Owner"
    or TargetResources[0].modifiedProperties contains "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

## Cost and governance

| Resource | SKU | Estimated Monthly Cost |
|---|---|---|
| Entra ID P2 (per user) | P2 | ~$9/user/month |
| PIM (included in P2) | P2 | Included |
| Conditional Access (P1) | P1 | ~$6/user/month |
| Access Reviews (P2) | P2 | Included |

Licensing note: Assign P2 licenses to administrative accounts that need PIM or access reviews. Enable Security Defaults at no charge for standard users.

## Core Entra ID identity features

1. Transparent token acquisition: Azure acquires tokens through Managed Identity endpoints or OIDC federation without manual assume-role API calls.
2. Tenant scope: One Entra ID tenant manages authentication across all subscriptions in the directory.
3. Conditional Access: Evaluates device state, user risk, and client location in addition to role membership.
4. Native PIM: Just-in-time access requests and auto-expiring role activations run directly within Entra ID.
5. B2B collaboration: External users retain home directory identities with mapped guest permissions in Azure.
