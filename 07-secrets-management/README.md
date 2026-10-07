# Project 7: Secrets Management with Azure Key Vault

## Overview

This project configures secret storage using Azure Key Vault, Managed Identities, and Key Vault References. It eliminates plaintext credentials from repositories, automates secret rotation with Event Grid, and mounts secrets into AKS pods using the Secrets Store CSI driver.

## Common secret storage mistakes

```
COMMON SECRET ANTI-PATTERNS
════════════════════════════

✗ ANTI-PATTERN 1: Hardcoded in Source Code
═══════════════════════════════════════════

# config.py - NEVER DO THIS
┌─────────────────────────────────────────────────────────────────┐
│  DATABASE_PASSWORD = "SuperSecret123!"                          │
│  AZURE_STORAGE_KEY  = "DefaultEndpointsProtocol=https;Account  │
│                        Name=mystorage;AccountKey=abc123..."     │
│  CLIENT_SECRET = "8x~Q8...dKE"  # App registration secret     │
└─────────────────────────────────────────────────────────────────┘
RISKS: In git history forever · Visible to all devs · No rotation

✗ ANTI-PATTERN 2: Connection Strings in App Config
══════════════════════════════════════════════════

# appsettings.json (checked into repo)
┌─────────────────────────────────────────────────────────────────┐
│  "ConnectionStrings": {                                         │
│    "Database": "Server=sql.database.windows.net;               │
│                 Password=MyProd@Pass123"                        │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
RISKS: Visible in Azure Portal config · Inconsistent environments

✗ ANTI-PATTERN 3: Pipeline Variables (Stored as Plain Text)
═══════════════════════════════════════════════════════════

# Azure DevOps Variable Group or GitHub Secrets
# Still a secret that needs rotation and can be leaked
DB_PASSWORD: "AnotherSecret456"   # Stored in CI/CD system
API_KEY: "sk_live_..."            # Rotated manually → easy to miss
```

## Architecture: Key Vault and Managed Identity

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    AZURE KEY VAULT SECRETS ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────────────┘

                         ┌─────────────────────────────────┐
                         │       AZURE KEY VAULT            │
                         │   (HSM-backed, RBAC-controlled) │
                         │                                 │
                         │  ┌───────────────────────────┐  │
                         │  │ Secrets:                  │  │
                         │  │  • db-connection-string   │  │
                         │  │  • storage-account-key    │  │  ← Auto-rotated
                         │  │  • api-key-external       │  │
                         │  │  • jwt-signing-key        │  │
                         │  └───────────────────────────┘  │
                         │  ┌───────────────────────────┐  │
                         │  │ Keys (HSM-protected):     │  │
                         │  │  • encryption-key (CMK)   │  │
                         │  │  • signing-key            │  │
                         │  └───────────────────────────┘  │
                         │  ┌───────────────────────────┐  │
                         │  │ Certificates:             │  │
                         │  │  • tls-cert (auto-renew)  │  │
                         │  │  • code-signing-cert      │  │
                         │  └───────────────────────────┘  │
                         └──────────────┬──────────────────┘
                                        │ RBAC (Key Vault
                                        │ Secrets User role)
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
          ┌──────────────┐    ┌──────────────────┐  ┌──────────────┐
          │  App Service  │    │  Azure Functions │  │  AKS Pod     │
          │  Managed      │    │  Managed Identity│  │  Workload    │
          │  Identity ✅  │    │  ✅ No secrets   │  │  Identity ✅  │
          │  (No secrets) │    │  in config       │  │  (OIDC)      │
          └──────────────┘    └──────────────────┘  └──────────────┘
```

## Implementation steps

### 1. Key Vault with Azure RBAC (Bicep)

```bicep
// keyvault.bicep

param location string = resourceGroup().location
param environment string
param appServiceManagedIdentityPrincipalId string
param appFunctionManagedIdentityPrincipalId string

var tags = {
  Environment: environment
  ManagedBy: 'Bicep'
  DataClassification: 'Confidential'
}

// Key Vault — RBAC authorization model (not legacy access policies)
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-app-${environment}-${uniqueString(resourceGroup().id)}'
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'premium'  // Premium for HSM-backed keys
    }
    tenantId: tenant().tenantId

    // ✅ RBAC authorization (preferred over access policies)
    enableRbacAuthorization: true

    // ✅ Soft delete + purge protection (prevents accidental/malicious deletion)
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true  // Cannot be disabled once enabled

    // ✅ Network restrictions
    networkAcls: {
      defaultAction: 'Deny'  // Deny all by default
      bypass: 'AzureServices'  // Allow Azure trusted services
      virtualNetworkRules: [
        {
          id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/rg-network-${environment}/providers/Microsoft.Network/virtualNetworks/vnet-hub-${environment}/subnets/snet-app'
          ignoreMissingVnetServiceEndpoint: false
        }
      ]
      ipRules: []  // No IP allowlisting — use Private Endpoints instead
    }

    // ✅ Public access disabled — Private Endpoint access only
    publicNetworkAccess: 'Disabled'

    // Enable diagnostic logging
    enabledForDeployment: false           // VMs should not fetch certs from KV directly
    enabledForDiskEncryption: true        // Allow Azure Disk Encryption
    enabledForTemplateDeployment: false   // ARM templates should not fetch secrets
  }
}

// ── RBAC Role Assignments ─────────────────────────────────────────────────

// App Service — Secrets User (read-only)
resource appServiceSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appServiceManagedIdentityPrincipalId, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'  // Key Vault Secrets User
    )
    principalId: appServiceManagedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Azure Functions — Secrets User
resource functionSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appFunctionManagedIdentityPrincipalId, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'  // Key Vault Secrets User
    )
    principalId: appFunctionManagedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Private Endpoint for Key Vault
resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: 'pep-kv-app-${environment}'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/rg-network-${environment}/providers/Microsoft.Network/virtualNetworks/vnet-hub-${environment}/subnets/snet-private-endpoints'
    }
    privateLinkServiceConnections: [
      {
        name: 'pep-kv-connection'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: ['vault']
        }
      }
    ]
  }
}

// Diagnostic settings — Send all Key Vault logs to Sentinel
resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-diagnostics-to-sentinel'
  scope: keyVault
  properties: {
    workspaceId: '/subscriptions/${subscription().subscriptionId}/resourceGroups/rg-security/providers/Microsoft.OperationalInsights/workspaces/law-sentinel-${environment}'
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: { days: 90, enabled: true }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: { days: 30, enabled: true }
      }
    ]
  }
}

output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
```

### 2. App Service Key Vault references

```bicep
// App Service with Key Vault references in configuration
// The App Service automatically fetches secrets from Key Vault — no code changes needed!

resource appService 'Microsoft.Web/sites@2023-01-01' = {
  name: 'app-myapp-${environment}'
  location: location
  identity: {
    type: 'SystemAssigned'  // ✅ Managed Identity — no service principal secret needed
  }
  properties: {
    siteConfig: {
      appSettings: [
        // ✅ Key Vault Reference — App Service fetches this automatically
        {
          name: 'DATABASE_CONNECTION_STRING'
          value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/db-connection-string/)'
        }
        {
          name: 'STORAGE_ACCOUNT_KEY'
          value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/storage-account-key/)'
        }
        {
          name: 'JWT_SIGNING_KEY'
          value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/jwt-signing-key/)'
        }
        // Regular (non-secret) config
        {
          name: 'ENVIRONMENT'
          value: environment
        }
      ]
    }
  }
}
```

### 3. Application code integration (Python and Node.js)

```python
# ✅ CORRECT: Fetch secrets using Managed Identity — no credentials in code!
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

def get_secret(secret_name: str, key_vault_url: str) -> str:
    """
    Fetch a secret from Azure Key Vault using Managed Identity.
    Works in: App Service, Azure Functions, AKS, Container Instances.
    Falls back to developer CLI credentials locally.
    """
    # DefaultAzureCredential tries multiple auth methods in order:
    # 1. AZURE_CLIENT_ID env var (Workload Identity in AKS)
    # 2. Managed Identity (App Service, Functions, VMs)
    # 3. Azure CLI (local development)
    # 4. Visual Studio / VS Code credentials
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)

    secret = client.get_secret(secret_name)
    return secret.value


# Usage
import os

KEY_VAULT_URL = os.getenv("KEY_VAULT_URL", "https://kv-app-prod-xxxxx.vault.azure.net/")

db_password = get_secret("db-connection-string", KEY_VAULT_URL)
api_key = get_secret("external-api-key", KEY_VAULT_URL)
```

```javascript
// ✅ CORRECT: Node.js / TypeScript with Managed Identity
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

const credential = new DefaultAzureCredential();
const client = new SecretClient(
  process.env.KEY_VAULT_URL!,
  credential
);

async function getSecret(secretName: string): Promise<string> {
  const secret = await client.getSecret(secretName);
  return secret.value!;
}

// Usage in application startup
const dbConnectionString = await getSecret("db-connection-string");
```

### 4. Automatic secret rotation

```bash
# Configure automatic rotation for storage account keys
# Key Vault + Azure Event Grid = auto-rotation when secret nears expiry

# Step 1: Create rotation function (Logic App or Azure Function)
az functionapp create \
  --resource-group rg-security \
  --name func-kv-rotation-${ENVIRONMENT} \
  --storage-account storage${ENVIRONMENT} \
  --consumption-plan-location eastus \
  --runtime python \
  --assign-identity '[system]'

# Step 2: Grant the rotation function Key Vault Secrets Officer
az role assignment create \
  --assignee-object-id $(az functionapp identity show \
      --name func-kv-rotation-${ENVIRONMENT} \
      --resource-group rg-security --query principalId -o tsv) \
  --role "Key Vault Secrets Officer" \
  --scope $(az keyvault show --name kv-app-prod --query id -o tsv)

# Step 3: Subscribe to Key Vault near-expiry event
az eventgrid event-subscription create \
  --name kv-secret-near-expiry-rotation \
  --source-resource-id $(az keyvault show --name kv-app-prod --query id -o tsv) \
  --included-event-types "Microsoft.KeyVault.SecretNearExpiry" \
  --endpoint $(az functionapp function show \
      --function-name rotate-storage-key \
      --name func-kv-rotation-prod \
      --resource-group rg-security \
      --query invokeUrlTemplate -o tsv)
```

### 5. AKS Secrets Store CSI driver

```yaml
# secrets-provider-class.yaml
# Mount Key Vault secrets as Kubernetes secrets (no hardcoded secrets in manifests)
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-kv-app-secrets
  namespace: app
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    clientID: ${MANAGED_IDENTITY_CLIENT_ID}  # User-Assigned Managed Identity
    keyvaultName: kv-app-prod-xxxxx
    tenantId: ${AZURE_TENANT_ID}
    objects: |
      array:
        - |
          objectName: db-connection-string
          objectType: secret
          objectVersion: ""           # Always get latest version
        - |
          objectName: api-key-external
          objectType: secret
          objectVersion: ""
  secretObjects:
    - secretName: app-secrets       # Creates a Kubernetes secret
      type: Opaque
      data:
        - objectName: db-connection-string
          key: DATABASE_URL
        - objectName: api-key-external
          key: API_KEY
---
# Pod using the secrets via volume mount and env vars
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: app
spec:
  template:
    spec:
      serviceAccountName: myapp-sa  # Has Workload Identity annotation
      volumes:
        - name: secrets-store
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: azure-kv-app-secrets
      containers:
        - name: myapp
          image: myacr.azurecr.io/myapp:latest
          volumeMounts:
            - name: secrets-store
              mountPath: "/mnt/secrets"
              readOnly: true
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: DATABASE_URL
```

## Security checklist

```
AZURE KEY VAULT SECURITY CHECKLIST
════════════════════════════════════

Key Vault Configuration
  ☐ Enable RBAC authorization (not legacy access policies)
  ☐ Enable soft delete (90-day minimum retention)
  ☐ Enable purge protection (irreversible — do this at creation)
  ☐ Disable public network access — use Private Endpoints
  ☐ Premium SKU for HSM-backed keys in production
  ☐ Diagnostic settings → Log Analytics / Sentinel

Access Control
  ☐ Managed Identity for all Azure workloads (no service principal secrets)
  ☐ Workload Identity Federation for CI/CD (GitHub Actions / ADO)
  ☐ Key Vault Secrets User role — applications
  ☐ Key Vault Secrets Officer role — automation/rotation
  ☐ Key Vault Administrator — only security team, via PIM
  ☐ No direct user access (use PIM for admin operations)

Secret Management
  ☐ All secrets have expiry dates configured (max 365 days)
  ☐ Automatic rotation for storage account keys, DB passwords
  ☐ Event Grid triggers for near-expiry notifications
  ☐ Secret naming convention enforced (env-service-name)
  ☐ No hardcoded connection strings anywhere in code/config
  ☐ App Service / Functions using Key Vault References

Monitoring
  ☐ Sentinel alert: Mass secret access (>20 in 5 mins)
  ☐ Sentinel alert: Secret access from unexpected IP/location
  ☐ Sentinel alert: Key Vault firewall bypassed
  ☐ Sentinel alert: Secret deletion attempted
  ☐ Key Vault availability metrics alert (SLA monitoring)
```

## Azure Key Vault core capabilities

| Feature | Key Vault Implementation |
|---|---|
| Automatic rotation | Event Grid triggers with Azure Function or Logic App |
| Replication | Multi-region deployment with secondary Key Vault |
| Secret types | String, binary secrets, cryptographic keys, certificates |
| Access model | Azure RBAC with granular data-plane roles |
| Kubernetes integration | Secrets Store CSI driver with Workload Identity |
| Certificate management | Integrated TLS issuance and automated renewal |
