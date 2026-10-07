# Azure Cloud Security Portfolio

A collection of production-ready Azure cloud security projects covering identity, network defense, DevSecOps, security posture management, SIEM logging, privileged access, secrets management, and threat modeling.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AZURE CLOUD SECURITY PORTFOLIO                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│   │  Identity   │  │   Network   │  │  DevSecOps  │  │ Compliance  │      │
│   │  & Access   │  │   Security  │  │             │  │  & Audit    │      │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘      │
│          │                │                │                │             │
│          ▼                ▼                ▼                ▼             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│   │  Project 1  │  │  Project 2  │  │  Project 3  │  │  Project 4  │      │
│   │  Entra ID   │  │  VNet+Bicep │  │  Azure      │  │  Defender   │      │
│   │  Cross-     │  │    IaC      │  │  DevOps     │  │  for Cloud  │      │
│   │  Tenant     │  │             │  │  Security   │  │   Audit     │      │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘      │
│                                                                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│   │  Project 5  │  │  Project 6  │  │  Project 7  │  │  Project 8  │      │
│   │  Sentinel   │  │ Break-Glass │  │ Azure Key   │  │   Threat    │      │
│   │  Centralized│  │  PIM Access │  │   Vault     │  │  Modeling   │      │
│   │  Logging    │  │             │  │  Secrets    │  │  (STRIDE)   │      │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Projects

| # | Project | Azure Services | Difficulty |
|---|---------|---------------|-----------|
| 01 | [Entra ID Cross-Tenant Access](./01-azure-entra-id-cross-tenant-access/README.md) | Entra ID, Managed Identity, Azure RBAC, B2B | ⭐⭐⭐ |
| 02 | [VNet Infrastructure as Code](./02-vnet-infrastructure-as-code/README.md) | Azure VNet, Bicep, NSG, Azure Firewall, DDoS | ⭐⭐⭐ |
| 03 | [CI/CD Security Pipeline](./03-cicd-security-pipeline/README.md) | Azure DevOps, GitHub Actions, Defender for DevOps | ⭐⭐⭐ |
| 04 | [Cloud Security Audit](./04-azure-security-audit/README.md) | Defender for Cloud, Azure Policy, Compliance Manager | ⭐⭐⭐ |
| 05 | [Centralized Logging](./05-centralized-logging/README.md) | Microsoft Sentinel, Log Analytics, Azure Monitor | ⭐⭐⭐ |
| 06 | [Break-Glass Access](./06-break-glass-access/README.md) | Azure PIM, Entra ID Roles, Conditional Access | ⭐⭐⭐ |
| 07 | [Secrets Management](./07-secrets-management/README.md) | Azure Key Vault, Managed Identity, RBAC | ⭐⭐⭐ |
| 08 | [Threat Modeling](./08-threat-modeling/README.md) | Microsoft Threat Modeling Tool, STRIDE, PASTA | ⭐⭐⭐⭐ |

## Prerequisites

```bash
# Azure CLI
az --version

# Bicep CLI (auto-installed via Azure CLI)
az bicep version

# Terraform (for IaC projects)
terraform version

# Azure PowerShell (optional)
Get-Module Az -ListAvailable
```

## Core Azure security principles

- Zero Trust: Verify identities explicitly and authorize each access request.
- Least privilege: Scoped Azure RBAC assignments with Managed Identities instead of service principal secrets.
- Defense in depth: Layered controls across NSGs, Azure Firewall, DDoS Protection, and Application Gateway WAF.
- Pipeline validation: Security scanners run during pull requests and build stages.
- Compliance as code: Azure Policy evaluates resource configurations against organizational baselines.

## Security framework references

- Azure Security Benchmark (ASB): Microsoft cloud security baseline recommendations.
- Microsoft Cloud Security Benchmark (MCSB): v1.0 security control mappings.
- CIS Azure Foundations Benchmark: Hardening guidelines from the Center for Internet Security.
- NIST 800-53 mapped to Azure: Controls mapped for FedRAMP authorizations.
- ISO 27001 on Azure: Control mappings for enterprise certification.
