# Project 2: Azure VNet Infrastructure as Code (Bicep + Terraform)

## Overview

This project provisions a hub-spoke Azure Virtual Network using Bicep and Terraform. The topology routes spoke traffic through Azure Firewall, isolates workloads in private subnets, enables DDoS Protection Standard, and eliminates direct internet exposure for VM management via Azure Bastion.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        AZURE REGION (East US)                                   │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                    VNet: 10.0.0.0/16  (Hub-Spoke)                        │  │
│  │                                                                           │  │
│  │  ┌──────────────────────────────────┐   ┌──────────────────────────────┐ │  │
│  │  │         HUB VNet (10.0.0.0/20)   │   │   SPOKE VNet (10.1.0.0/16)   │ │  │
│  │  │                                  │   │                               │ │  │
│  │  │  ┌────────────────────────────┐  │   │  ┌─────────────────────────┐ │ │  │
│  │  │  │    AzureFirewallSubnet     │  │   │  │   App Subnet (Private)  │ │ │  │
│  │  │  │    10.0.0.0/26             │  │   │  │   10.1.1.0/24           │ │ │  │
│  │  │  │  ┌─────────────────────┐  │  │   │  │  NSG: Allow 443 only    │ │ │  │
│  │  │  │  │  Azure Firewall     │  │  │VNet│  │  UDR → Azure Firewall   │ │ │  │
│  │  │  │  │  Premium + IDS/IPS  │──┼──┼───┼─▶│                         │ │ │  │
│  │  │  │  └─────────────────────┘  │  │Peer│  └─────────────────────────┘ │ │  │
│  │  │  └────────────────────────────┘  │ing │  ┌─────────────────────────┐ │ │  │
│  │  │  ┌────────────────────────────┐  │   │  │   DB Subnet (Private)   │ │ │  │
│  │  │  │  GatewaySubnet 10.0.1.0/27 │  │   │  │   10.1.2.0/24           │ │ │  │
│  │  │  │  ┌──────────────────────┐  │  │   │  │  NSG: Deny all inbound  │ │ │  │
│  │  │  │  │ VPN Gateway / ExpressR│  │  │   │  │  Private Endpoint only  │ │ │  │
│  │  │  │  └──────────────────────┘  │  │   │  └─────────────────────────┘ │ │  │
│  │  │  └────────────────────────────┘  │   └──────────────────────────────┘ │  │
│  │  │  ┌────────────────────────────┐  │                                     │  │
│  │  │  │  BastionSubnet 10.0.2.0/27 │  │   DDoS Protection Standard          │  │
│  │  │  │  Azure Bastion (No public  │  │   applies to all public IPs         │  │
│  │  │  │  SSH/RDP exposed)          │  │                                     │  │
│  │  │  └────────────────────────────┘  │                                     │  │
│  │  └──────────────────────────────────┘                                     │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```
## Implementation with Bicep

### `main.bicep` — Hub VNet with Azure Firewall

```bicep
@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Environment (dev, staging, prod)')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'prod'

@description('Hub VNet address space')
param hubAddressPrefix string = '10.0.0.0/20'

var tags = {
  Environment: environment
  ManagedBy: 'Bicep'
  SecurityClassification: 'Internal'
  Project: 'NetworkSecurity'
}

// ─────────────────────────────────────────────────────
// HUB VIRTUAL NETWORK
// ─────────────────────────────────────────────────────
resource hubVNet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-hub-${environment}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [hubAddressPrefix]
    }
    enableDdosProtection: true
    ddosProtectionPlan: {
      id: ddosProtectionPlan.id
    }
    subnets: [
      {
        name: 'AzureFirewallSubnet'   // Name must be exactly this for Azure Firewall
        properties: {
          addressPrefix: '10.0.0.0/26'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
      {
        name: 'AzureBastionSubnet'    // Name must be exactly this for Azure Bastion
        properties: {
          addressPrefix: '10.0.1.0/27'
        }
      }
      {
        name: 'GatewaySubnet'         // Name must be exactly this for VPN/ExpressRoute
        properties: {
          addressPrefix: '10.0.2.0/27'
        }
      }
      {
        name: 'snet-management'
        properties: {
          addressPrefix: '10.0.3.0/28'
          networkSecurityGroup: {
            id: managementNsg.id
          }
        }
      }
    ]
  }
}

// ─────────────────────────────────────────────────────
// DDOS PROTECTION PLAN (Standard)
// ─────────────────────────────────────────────────────
resource ddosProtectionPlan 'Microsoft.Network/ddosProtectionPlans@2023-05-01' = {
  name: 'ddos-plan-${environment}'
  location: location
  tags: tags
}

// ─────────────────────────────────────────────────────
// NETWORK SECURITY GROUPS (NSGs)
// ─────────────────────────────────────────────────────
resource managementNsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-management-${environment}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          description: 'Explicit deny-all — Azure Firewall handles allow rules'
        }
      }
      {
        name: 'Allow-AzureBastion-SSH'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRanges: ['22', '3389']
          sourceAddressPrefix: '10.0.1.0/27'  // Bastion subnet only
          destinationAddressPrefix: '*'
          description: 'Allow SSH/RDP only from Azure Bastion subnet'
        }
      }
    ]
  }
}

// ─────────────────────────────────────────────────────
// AZURE FIREWALL PREMIUM
// ─────────────────────────────────────────────────────
resource firewallPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'pip-firewall-${environment}'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {
  name: 'afwp-${environment}'
  location: location
  tags: tags
  properties: {
    sku: {
      tier: 'Premium'  // Premium for TLS inspection + IDPS
    }
    threatIntelMode: 'Alert'
    intrusionDetection: {
      mode: 'Alert'  // Change to 'Deny' for production after tuning
    }
    dnsSettings: {
      enableProxy: true
    }
  }
}

resource azureFirewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {
  name: 'afw-hub-${environment}'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Premium'
    }
    firewallPolicy: {
      id: firewallPolicy.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: hubVNet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: firewallPublicIp.id
          }
        }
      }
    ]
  }
}

// ─────────────────────────────────────────────────────
// AZURE BASTION (No public RDP/SSH exposure)
// ─────────────────────────────────────────────────────
resource bastionPublicIp 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: 'pip-bastion-${environment}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource azureBastion 'Microsoft.Network/bastionHosts@2023-05-01' = {
  name: 'bas-hub-${environment}'
  location: location
  tags: tags
  sku: { name: 'Standard' }  // Standard enables native client + tunneling
  properties: {
    scaleUnits: 2
    enableIpConnect: true     // Required for SSH/RDP tunneling via native client
    enableTunneling: true
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: hubVNet.properties.subnets[1].id
          }
          publicIPAddress: {
            id: bastionPublicIp.id
          }
        }
      }
    ]
  }
}

// ─────────────────────────────────────────────────────
// NSG FLOW LOGS → TRAFFIC ANALYTICS
// ─────────────────────────────────────────────────────
resource networkWatcher 'Microsoft.Network/networkWatchers@2023-05-01' existing = {
  name: 'NetworkWatcher_${location}'
  scope: resourceGroup('NetworkWatcherRG')
}

resource nsgFlowLog 'Microsoft.Network/networkWatchers/flowLogs@2023-05-01' = {
  parent: networkWatcher
  name: 'fl-management-nsg-${environment}'
  location: location
  properties: {
    storageId: storageAccount.id
    enabled: true
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceId: logAnalyticsWorkspace.properties.customerId
        workspaceRegion: location
        workspaceResourceId: logAnalyticsWorkspace.id
        trafficAnalyticsInterval: 10  // 10-minute intervals
      }
    }
    format: {
      type: 'JSON'
      version: 2
    }
    retentionPolicy: {
      days: 90
      enabled: true
    }
  }
}
```

## Terraform configuration

```hcl
# variables.tf
variable "location" {
  description = "Azure region"
  default     = "eastus"
}

variable "environment" {
  description = "Environment name"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# main.tf
resource "azurerm_resource_group" "network" {
  name     = "rg-network-${var.environment}"
  location = var.location
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "azurerm_network_ddos_protection_plan" "main" {
  name                = "ddos-plan-${var.environment}"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
}

resource "azurerm_virtual_network" "hub" {
  name                = "vnet-hub-${var.environment}"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  address_space       = ["10.0.0.0/20"]

  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.main.id
    enable = true
  }
}

resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"  # Must be this exact name
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.0.0/26"]
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"  # Must be this exact name
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.1.0/27"]
}

resource "azurerm_network_security_group" "management" {
  name                = "nsg-management-${var.environment}"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name

  security_rule {
    name                       = "Allow-Bastion-SSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "3389"]
    source_address_prefix      = "10.0.1.0/27"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Deny-All-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
```

## Security hardening checklist

```
AZURE NETWORK SECURITY HARDENING
══════════════════════════════════

Network Architecture
  ☐ Hub-Spoke topology with Azure Firewall in hub
  ☐ All spoke traffic routes through hub firewall (UDR)
  ☐ No direct internet access from spoke VNets
  ☐ DDoS Protection Standard enabled on all VNets with public IPs
  ☐ Azure Bastion deployed (no public RDP/SSH)

NSG Best Practices
  ☐ Explicit deny-all rules at lowest priority (4096)
  ☐ NSG flow logs enabled with Traffic Analytics
  ☐ NSGs applied at subnet level (not NIC level)
  ☐ No Any/Any allow rules in production NSGs
  ☐ Service Tags used instead of IPs where possible

Azure Firewall
  ☐ Azure Firewall Premium tier (TLS inspection + IDPS)
  ☐ Threat Intelligence mode set to Alert/Deny
  ☐ IDPS mode configured (Alert → tune → Deny)
  ☐ DNS proxy enabled (all VMs use Firewall DNS)
  ☐ Application rules for FQDN-based filtering

Private Endpoints
  ☐ All PaaS services (Storage, SQL, Key Vault) use Private Endpoints
  ☐ Public access disabled on all PaaS services
  ☐ Private DNS zones configured for all private endpoints
  ☐ No service endpoints (prefer Private Endpoints)

Monitoring
  ☐ NSG Flow Logs → Log Analytics (Traffic Analytics)
  ☐ Azure Firewall logs → Log Analytics
  ☐ Diagnostic settings enabled on all network resources
  ☐ Azure Network Watcher enabled in all regions
```

## Deployment commands

```bash
# Login to Azure
az login
az account set --subscription "<subscription-id>"

# Create resource group
az group create \
  --name rg-network-prod \
  --location eastus \
  --tags Environment=prod ManagedBy=Bicep

# Deploy hub network using Bicep
az deployment group create \
  --resource-group rg-network-prod \
  --template-file main.bicep \
  --parameters environment=prod \
  --parameters location=eastus \
  --what-if  # Preview changes first

# Confirm and deploy
az deployment group create \
  --resource-group rg-network-prod \
  --template-file main.bicep \
  --parameters environment=prod

# Validate NSG rules
az network nsg rule list \
  --nsg-name nsg-management-prod \
  --resource-group rg-network-prod \
  --output table
```

## NSG flow log analytics query (KQL)

```kql
// Top denied flows by source IP (potential attack traffic)
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where FlowStatus_s == "D"  // Denied flows
| summarize DeniedFlows = count() by SrcIP_s, DestPort_d, L4Protocol_s
| order by DeniedFlows desc
| take 20
```
