# Project 4: Azure Cloud Security Audit with Microsoft Defender for Cloud

## Overview

This project audits Azure subscription posture using Microsoft Defender for Cloud, Azure Policy initiatives, and Microsoft Compliance Manager. It automates CIS benchmark assignments, exports resource hygiene checks via Azure CLI, and tracks compliance drift with Log Analytics queries.

## Security audit flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   AZURE SECURITY AUDIT ARCHITECTURE                             │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐    ┌──────────────────────────────────────────────────┐
│   Azure Resources   │    │          MICROSOFT DEFENDER FOR CLOUD            │
│  (All Subscriptions)│───▶│                                                  │
└─────────────────────┘    │  ┌────────────────┐   ┌──────────────────────┐  │
                           │  │  Secure Score  │   │  Regulatory           │  │
┌─────────────────────┐    │  │  0–100%        │   │  Compliance:          │  │
│  Azure Policy       │───▶│  │  (Your posture)│   │  • CIS Azure v1.4     │  │
│  (Guardrails)       │    │  └────────────────┘   │  • PCI DSS v4         │  │
└─────────────────────┘    │                       │  • NIST 800-53        │  │
                           │  ┌────────────────┐   │  • ISO 27001          │  │
┌─────────────────────┐    │  │ Recommendations│   │  • SOC 2 Type II      │  │
│  Entra ID / RBAC    │───▶│  │ (Priority:     │   └──────────────────────┘  │
│  (Identity signals) │    │  │  High/Med/Low) │                              │
└─────────────────────┘    │  └────────────────┘   ┌──────────────────────┐  │
                           │                       │  Workload Protection: │  │
                           │  ┌────────────────┐   │  • Servers            │  │
                           │  │  Alerts &      │   │  • Containers (AKS)   │  │
                           │  │  Incidents     │   │  • Databases          │  │
                           │  │  (Threat Intel)│   │  • App Service        │  │
                           │  └────────────────┘   │  • Key Vault          │  │
                           └──────────────────────  └──────────────────────┘  │
                                                    └──────────────────────────┘
```
## Implementation steps

### 1. Enable Defender for Cloud plans (Bicep)

```bicep
// Enable Microsoft Defender for Cloud plans across a subscription
// defender-plans.bicep

@description('Defender plan pricing tier')
@allowed(['Free', 'Standard'])
param pricingTier string = 'Standard'

// Enable Defender for Servers
resource defenderServers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: pricingTier
    subPlan: 'P2'  // P2 includes file integrity monitoring + adaptive controls
  }
}

// Enable Defender for Containers (AKS + ACR + Registry)
resource defenderContainers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: pricingTier
  }
}

// Enable Defender for Storage
resource defenderStorage 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'StorageAccounts'
  properties: {
    pricingTier: pricingTier
  }
}

// Enable Defender for SQL
resource defenderSql 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'SqlServers'
  properties: {
    pricingTier: pricingTier
  }
}

// Enable Defender for Key Vault
resource defenderKeyVault 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'KeyVaults'
  properties: {
    pricingTier: pricingTier
  }
}

// Enable Defender for App Service
resource defenderAppService 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'AppServices'
  properties: {
    pricingTier: pricingTier
  }
}

// Enable Defender for DNS (detect command-and-control channels)
resource defenderDns 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Dns'
  properties: {
    pricingTier: pricingTier
  }
}
```

### 2. Assign CIS benchmark policy initiative

```bash
# Assign the CIS Azure Foundations Benchmark v1.4 policy initiative
az policy assignment create \
  --name "CIS-Azure-v1-4" \
  --display-name "CIS Microsoft Azure Foundations Benchmark v1.4" \
  --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/612b5213-9160-4969-8578-1518bd2a000c" \
  --scope "/subscriptions/<subscription-id>" \
  --identity-type SystemAssigned \
  --location eastus \
  --parameters '{
    "logAnalyticsWorkspaceId": {
      "value": "/subscriptions/<sub-id>/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/law-security"
    }
  }'

# Assign NIST SP 800-53 Rev 5
az policy assignment create \
  --name "NIST-800-53-R5" \
  --display-name "NIST SP 800-53 Rev. 5" \
  --policy-set-definition "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f" \
  --scope "/subscriptions/<subscription-id>" \
  --identity-type SystemAssigned \
  --location eastus
```

### 3. Custom Azure Policy for encryption at rest

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Storage/storageAccounts"
        },
        {
          "field": "Microsoft.Storage/storageAccounts/encryption.keySource",
          "notEquals": "Microsoft.Keyvault"
        }
      ]
    },
    "then": {
      "effect": "Deny"
    }
  },
  "metadata": {
    "category": "Storage",
    "version": "1.0.0"
  },
  "displayName": "Storage accounts must use customer-managed keys",
  "description": "Deny storage accounts not using Azure Key Vault CMK for encryption"
}
```

```bash
# Create the custom policy
az policy definition create \
  --name "require-storage-cmk" \
  --display-name "Storage must use Customer Managed Keys" \
  --description "Deny storage accounts without CMK encryption" \
  --rules storage-cmk-policy.json \
  --mode All \
  --subscription <subscription-id>

# Assign the policy
az policy assignment create \
  --name "enforce-storage-cmk" \
  --policy "require-storage-cmk" \
  --scope "/subscriptions/<subscription-id>"
```

### 4. Automated security audit script

```bash
#!/bin/bash
# azure-security-audit.sh
# Performs a comprehensive Azure security audit

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
OUTPUT_DIR="./audit-results-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

echo "═══════════════════════════════════════════════════"
echo "  AZURE SECURITY AUDIT — $(date)"
echo "  Subscription: $SUBSCRIPTION_ID"
echo "═══════════════════════════════════════════════════"

# ── 1. Entra ID Security ──────────────────────────────
echo ""
echo "[1] ENTRA ID SECURITY"
echo "─────────────────────"

# Check MFA status for Global Admins
echo "→ Checking Conditional Access policies..."
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --query "value[].{Name:displayName, State:state}" \
  --output table 2>/dev/null | tee "$OUTPUT_DIR/conditional-access.txt"

# Check for guest users with Owner role
echo "→ Checking for guest users with high-privilege roles..."
az role assignment list \
  --all \
  --query "[?principalType=='Guest' && (roleDefinitionName=='Owner' || roleDefinitionName=='Contributor')].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" \
  --output table | tee "$OUTPUT_DIR/guest-high-privilege.txt"

# ── 2. Subscription-Level RBAC ───────────────────────
echo ""
echo "[2] SUBSCRIPTION RBAC"
echo "──────────────────────"

# Owner assignments at subscription scope (should be minimal)
echo "→ Owner role assignments at subscription scope:"
az role assignment list \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --query "[?roleDefinitionName=='Owner'].{Principal:principalName, PrincipalType:principalType}" \
  --output table | tee "$OUTPUT_DIR/owner-assignments.txt"

# ── 3. Storage Account Security ───────────────────────
echo ""
echo "[3] STORAGE SECURITY"
echo "────────────────────"

echo "→ Storage accounts with public access enabled:"
az storage account list \
  --query "[?allowBlobPublicAccess==\`true\`].{Name:name, ResourceGroup:resourceGroup, PublicAccess:allowBlobPublicAccess}" \
  --output table | tee "$OUTPUT_DIR/public-storage.txt"

echo "→ Storage accounts without HTTPS enforcement:"
az storage account list \
  --query "[?enableHttpsTrafficOnly==\`false\`].{Name:name, ResourceGroup:resourceGroup}" \
  --output table | tee "$OUTPUT_DIR/http-storage.txt"

echo "→ Storage accounts not using private endpoints:"
az storage account list \
  --query "[?publicNetworkAccess=='Enabled'].{Name:name, ResourceGroup:resourceGroup}" \
  --output table | tee "$OUTPUT_DIR/public-network-storage.txt"

# ── 4. Key Vault Security ─────────────────────────────
echo ""
echo "[4] KEY VAULT SECURITY"
echo "──────────────────────"

echo "→ Key Vaults with public network access:"
az keyvault list \
  --query "[?properties.publicNetworkAccess=='Enabled'].{Name:name, ResourceGroup:resourceGroup}" \
  --output table | tee "$OUTPUT_DIR/public-keyvault.txt"

echo "→ Key Vaults without soft delete (CRITICAL):"
az keyvault list \
  --query "[?properties.enableSoftDelete==\`false\` || properties.enableSoftDelete==null].{Name:name}" \
  --output table | tee "$OUTPUT_DIR/no-softdelete-kv.txt"

echo "→ Key Vaults without purge protection:"
az keyvault list \
  --query "[?properties.enablePurgeProtection!=\`true\`].{Name:name, ResourceGroup:resourceGroup}" \
  --output table | tee "$OUTPUT_DIR/no-purge-protection-kv.txt"

# ── 5. Network Security ───────────────────────────────
echo ""
echo "[5] NETWORK SECURITY"
echo "────────────────────"

echo "→ NSGs with Any/Any allow rules:"
az network nsg list --query "[].{NSG:name, RG:resourceGroup}" --output tsv | while read nsg rg; do
  az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" \
    --query "[?access=='Allow' && sourceAddressPrefix=='*' && destinationPortRange=='*'].{NSG:'$nsg', Rule:name, Priority:priority}" \
    --output table 2>/dev/null
done | tee "$OUTPUT_DIR/permissive-nsg-rules.txt"

echo "→ VMs with public IPs (directly exposed):"
az vm list-ip-addresses \
  --query "[].{VM:virtualMachine.name, PublicIP:virtualMachine.network.publicIpAddresses[0].ipAddress}" \
  --output table | tee "$OUTPUT_DIR/vms-with-public-ips.txt"

# ── 6. Defender for Cloud Score ───────────────────────
echo ""
echo "[6] DEFENDER FOR CLOUD"
echo "──────────────────────"

echo "→ Secure Score:"
az security secure-score list \
  --query "[].{Score:score.current, Max:score.max, Percentage:score.percentage}" \
  --output table | tee "$OUTPUT_DIR/secure-score.txt"

echo "→ Top High-Severity Recommendations:"
az security assessment list \
  --query "[?status.code=='Unhealthy' && metadata.severity=='High'].{Name:metadata.displayName, Resource:resourceDetails.id}" \
  --output table 2>/dev/null | head -20 | tee "$OUTPUT_DIR/high-severity-recs.txt"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  AUDIT COMPLETE. Results saved to: $OUTPUT_DIR"
echo "═══════════════════════════════════════════════════"
```

### 5. Secure Score KQL queries

```kql
// Microsoft Sentinel / Log Analytics — Secure Score over time
SecurityResources
| where type == "microsoft.security/securescores"
| extend scoreData = parse_json(properties)
| project TimeGenerated, Score = todouble(scoreData.score.current), 
          MaxScore = todouble(scoreData.score.max),
          Percentage = todouble(scoreData.score.percentage)
| order by TimeGenerated desc
| take 30
```

```kql
// High-severity unresolved recommendations
SecurityResources
| where type == "microsoft.security/assessments"
| extend props = parse_json(properties)
| where props.status.code == "Unhealthy"
| extend Severity = tostring(props.metadata.severity)
| where Severity == "High"
| project Resource = id, Recommendation = tostring(props.metadata.displayName),
          Severity, RemediationSteps = tostring(props.metadata.remediationDescription)
| order by Recommendation
```

## Security audit baseline checklist

```
MICROSOFT DEFENDER FOR CLOUD BASELINE
═══════════════════════════════════════

Defender Plans
  ☐ Defender for Servers (P2) enabled
  ☐ Defender for Containers enabled
  ☐ Defender for Storage enabled
  ☐ Defender for Key Vault enabled
  ☐ Defender for SQL enabled
  ☐ Defender for App Service enabled
  ☐ Defender CSPM enabled (Cloud Security Posture Management)

Secure Score Targets
  ☐ Secure Score > 80% baseline
  ☐ All High-severity recommendations remediated
  ☐ No "Quick Fix" recommendations left unfixed
  ☐ Weekly Secure Score review in Security team

Azure Policy
  ☐ CIS Azure Benchmark v1.4 initiative assigned
  ☐ NIST 800-53 initiative assigned (if required)
  ☐ Custom policies for org-specific controls
  ☐ Policy compliance > 90% across subscriptions
  ☐ Policy exemptions documented and time-limited

Identity (from audit perspective)
  ☐ No accounts inactive > 90 days
  ☐ No guest users with privileged roles
  ☐ MFA enforced for all users (Conditional Access)
  ☐ PIM enabled — no permanent privileged role assignments
  ☐ Service principal secrets expiry < 90 days

Storage
  ☐ All blob containers — public access disabled
  ☐ HTTPS-only traffic enforced on all storage
  ☐ Minimum TLS 1.2 enforced
  ☐ Storage private endpoints configured
  ☐ Soft delete enabled (blobs + containers)

Key Vault
  ☐ Soft delete enabled (90-day minimum)
  ☐ Purge protection enabled
  ☐ RBAC authorization model (not access policies)
  ☐ Private endpoint access only
  ☐ Diagnostic logs sent to Log Analytics

Network
  ☐ No inbound RDP (3389) or SSH (22) from Internet in NSGs
  ☐ Azure Firewall Premium deployed in hub
  ☐ DDoS Protection Standard enabled
  ☐ Azure Bastion for VM access (no public IPs on VMs)
  ☐ NSG Flow Logs enabled and sent to Log Analytics
```
