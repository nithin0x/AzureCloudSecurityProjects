# Project 8: Threat Modeling for Azure Architectures (STRIDE + Microsoft TMT)

## Overview

This project models threats against an Azure three-tier web application using the STRIDE and PASTA methodologies. It documents trust boundaries, identifies attack paths across components, maps mitigations to Azure native controls, and provides a report template for architecture reviews.

## STRIDE framework for Azure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    STRIDE THREAT CATEGORIES ON AZURE                            │
├────────────────┬──────────────┬──────────────────────────────────────────────────┤
│ STRIDE         │ Threat Type  │ Azure Mitigations                                │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ S — Spoofing   │ Identity     │ Entra ID MFA, Conditional Access, Managed        │
│                │              │ Identity, Certificate Auth, FIDO2 passkeys        │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ T — Tampering  │ Integrity    │ Key Vault (CMK), RBAC write controls, Immutable  │
│                │              │ Storage, Azure Policy deny effects, TLS 1.3       │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ R — Repudiation│ Non-repud.   │ Azure Monitor Activity Logs, Sentinel, Key Vault │
│                │              │ audit logs, Immutable Log Analytics workspace      │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ I — Info Discl │ Confidential.│ Azure Key Vault, Private Endpoints, VNET         │
│                │              │ isolation, CMK encryption, Purview DLP            │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ D — DoS        │ Availability │ DDoS Protection Standard, Azure Firewall rate     │
│                │              │ limits, API Management throttling, WAF, CDN       │
├────────────────┼──────────────┼──────────────────────────────────────────────────┤
│ E — Elevation  │ Authorization│ Azure RBAC, PIM (JIT), Conditional Access,       │
│                │              │ Entra ID Protection, Management Group policies    │
└────────────────┴──────────────┴──────────────────────────────────────────────────┘
```

## Threat modeling an Azure web application

### Architecture diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SYSTEM BEING THREAT MODELED                                  │
│                    Azure 3-Tier Web Application                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

   Internet          Azure             Application          Data
   ─────────         ─────             ───────────          ────
   [User Browser]──▶[Azure Front     ──▶[App Service]──▶[Azure SQL]
                     Door + WAF]          │                   │
                          │              │App Service         │Azure Key
                          │              │ Managed Identity   │Vault (CMK)
                   [Azure DDoS          │                   │
                    Protection]        [Azure Cache          │Private
                          │             for Redis]           │Endpoint
                   [Azure Firewall]       │                   │
                                       [Azure Blob           │
                                        Storage]             │
                                                        [Azure Monitor
                                                         + Sentinel]
```

### Data flow diagram trust boundaries

```
TRUST BOUNDARIES AND DATA FLOWS
════════════════════════════════

[1] Internet → Azure Front Door (Trust Boundary: Public Internet → Azure Edge)
    Flow: HTTPS requests (port 443)
    Data: User input, authentication tokens

[2] Azure Front Door → App Service (Trust Boundary: Azure Edge → Application)
    Flow: HTTPS (port 443), WAF-filtered
    Data: Sanitized user requests, custom headers

[3] App Service → Azure SQL (Trust Boundary: Application → Data Tier)
    Flow: TLS 1.2+ on port 1433, via Private Endpoint
    Data: SQL queries, sensitive PII

[4] App Service → Azure Key Vault (Trust Boundary: Application → Secrets Store)
    Flow: HTTPS via Managed Identity token, Private Endpoint
    Data: Connection strings, API keys, encryption keys

[5] App Service → Redis Cache (Internal, same VNet)
    Flow: TLS on port 6380
    Data: Session data, cached query results

[6] All Services → Azure Monitor / Sentinel
    Flow: Diagnostic logs, metrics
    Data: Audit events, access patterns
```

## STRIDE analysis: Internet to Front Door

```
BOUNDARY: Internet → Azure Front Door + WAF
════════════════════════════════════════════

┌─── SPOOFING ─────────────────────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: Attacker impersonates legitimate user (stolen session token)        │
│  RISK: HIGH                                                                  │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ Entra ID authentication with Conditional Access                          │
│  ✅ Short-lived access tokens (1 hour) + refresh token rotation              │
│  ✅ Continuous Access Evaluation (CAE) — real-time token revocation          │
│  ✅ Azure Front Door WAF — bot protection + rate limiting                    │
│  ✅ Entra ID Identity Protection — risky sign-in detection                   │
│                                                                              │
│  Residual Risk: MEDIUM (token theft between rotation windows)                │
│  Control Gap: Consider PKCE for SPA apps; short session lifetimes            │
└──────────────────────────────────────────────────────────────────────────────┘

┌─── TAMPERING ────────────────────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: Man-in-the-middle attack, request manipulation                      │
│  RISK: HIGH                                                                  │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ HTTPS enforced (HTTP redirects to HTTPS in Front Door)                   │
│  ✅ TLS 1.2+ minimum (TLS 1.0/1.1 disabled)                                 │
│  ✅ Azure Front Door managed TLS certificate (auto-renewed)                  │
│  ✅ HSTS headers configured                                                  │
│  ✅ Content Security Policy (CSP) headers                                    │
│                                                                              │
│  Residual Risk: LOW                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

┌─── REPUDIATION ──────────────────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: User denies performing an action (fraud, compliance gap)            │
│  RISK: MEDIUM                                                                │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ Front Door access logs → Log Analytics (retained 90+ days)               │
│  ✅ App Service application logs → Log Analytics                             │
│  ✅ Entra ID sign-in logs (includes IP, device, timestamp)                   │
│  ✅ Immutable storage for audit logs (WORM policies)                         │
│                                                                              │
│  Residual Risk: LOW                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

┌─── INFORMATION DISCLOSURE ───────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: Sensitive data exposed via verbose error messages / API responses   │
│  RISK: HIGH                                                                  │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ Azure Front Door WAF — blocks known attack patterns (OWASP rules)         │
│  ✅ Custom error pages (no stack traces in production)                        │
│  ✅ Microsoft Defender for App Service — web app vulnerability detection     │
│  ✅ API Management (APIM) — response filtering, schema validation            │
│                                                                              │
│  Residual Risk: MEDIUM — App-level error handling must be reviewed           │
│  Action Item: Implement custom error handling middleware                     │
└──────────────────────────────────────────────────────────────────────────────┘

┌─── DENIAL OF SERVICE ────────────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: DDoS attack overwhelming application; API abuse                    │
│  RISK: HIGH (internet-facing service)                                       │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ Azure DDoS Protection Standard (L3/L4 volumetric attack mitigation)      │
│  ✅ Azure Front Door WAF rate limiting rules                                 │
│  ✅ Azure Front Door — global anycast (absorbs volume)                       │
│  ✅ App Service Auto-scale (handle legitimate traffic spikes)                │
│  ✅ Redis Cache (reduces DB load during high traffic)                        │
│                                                                              │
│  Residual Risk: MEDIUM — L7 application DoS (slow loris, etc.) requires     │
│  WAF custom rules and load testing validation                               │
│  Action Item: Configure WAF custom rules for rate limiting per IP/session    │
└──────────────────────────────────────────────────────────────────────────────┘

┌─── ELEVATION OF PRIVILEGE ───────────────────────────────────────────────────┐
│                                                                              │
│  THREAT: Unauthenticated access to admin endpoints; IDOR vulnerabilities     │
│  RISK: CRITICAL                                                              │
│                                                                              │
│  Azure Mitigations:                                                          │
│  ✅ Entra ID authentication required for all endpoints                       │
│  ✅ Azure RBAC — scoped permissions at resource level                        │
│  ✅ App Service — AuthN/AuthZ module (Easy Auth)                             │
│  ✅ Conditional Access — require compliant device for admin endpoints        │
│  ✅ APIM — authorization policy per API operation                            │
│                                                                              │
│  Residual Risk: MEDIUM — IDOR depends on application-level authorization    │
│  Action Item: Implement attribute-based access control in application layer  │
└──────────────────────────────────────────────────────────────────────────────┘
```

## STRIDE analysis: App Service to Azure SQL

```
BOUNDARY: App Service → Azure SQL Database
═══════════════════════════════════════════

Threat: SQL Injection → Information Disclosure / Tampering
─────────────────────────────────────────────────────────
Risk: CRITICAL
Azure Mitigations:
  ✅ Defender for SQL — Advanced Threat Protection (ATP)
     • Detects SQL injection patterns in real-time
     • Unusual query patterns (data exfiltration)
  ✅ Azure SQL Audit → Log Analytics (query logging)
  ✅ Azure SQL Always Encrypted (column-level encryption)
  ✅ Private Endpoint (SQL not exposed to internet)
  ✅ Firewall — only App Service Managed Identity allowed
Action: Use parameterized queries (ORM prevents SQLi); enable Defender ATP alerts

Threat: Credential Theft → Unauthorized Data Access (Spoofing)
─────────────────────────────────────────────────────────────
Risk: HIGH
Azure Mitigations:
  ✅ Managed Identity authentication (no SQL password in config!)
  ✅ Azure AD-only authentication enforced on SQL server
  ✅ No local SQL accounts enabled
Action: Enable Azure AD-only auth via Azure Policy; audit SQL logins

Threat: Data Exfiltration (Information Disclosure)
─────────────────────────────────────────────────
Risk: HIGH
Azure Mitigations:
  ✅ Microsoft Purview — data classification + DLP policies
  ✅ Azure SQL Dynamic Data Masking (non-admin users see masked data)
  ✅ Private Endpoint (no public SQL endpoint)
  ✅ Defender for SQL alert: "Data exfiltration" pattern
Action: Enable Dynamic Data Masking for PII columns; configure Purview scanning
```

## Threat model report template

```markdown
## Threat Model Report: [Application Name]
**Date**: [Date]  
**Version**: 1.0  
**Author**: [Security Team]  
**Review Date**: [90 days from now]

### System Overview
[Brief description of the Azure architecture being modeled]

### Assets
| Asset | Classification | Owner | Location |
|---|---|---|---|
| Customer PII | Confidential | Product | Azure SQL |
| Authentication tokens | Secret | Platform | Redis Cache |
| Encryption keys | Top Secret | Security | Key Vault HSM |

### Trust Boundaries
| ID | Boundary | Crossing Components |
|---|---|---|
| TB-1 | Internet → Azure Edge | User → Front Door |
| TB-2 | Azure Edge → Application | Front Door → App Service |
| TB-3 | Application → Data | App Service → Azure SQL |
| TB-4 | Application → Secrets | App Service → Key Vault |

### Threats Identified
| ID | STRIDE | Threat | Risk | Mitigation | Status |
|---|---|---|---|---|---|
| T-001 | S | Token theft | HIGH | Entra ID CAE + short tokens | Mitigated |
| T-002 | D | DDoS | HIGH | DDoS Standard + WAF | Mitigated |
| T-003 | I | SQL Injection | CRITICAL | Defender ATP + ORM | Mitigated |
| T-004 | E | IDOR | MEDIUM | App-level ABAC | Open |
| T-005 | I | Data exfiltration | HIGH | Purview DLP | In Progress |

### Open Risks
[Document accepted or in-progress risks with justification and timeline]

### Review Schedule
- Quarterly: Full threat model review
- Per release: New trust boundaries or data flows
- Annually: Complete architecture re-assessment
```

## Microsoft Threat Modeling Tool setup

```bash
# Microsoft TMT runs on Windows
# Download from: https://aka.ms/threatmodelingtool

# Using the Azure Stencils (pre-built threat templates)
# 1. Open TMT
# 2. File → New → Azure Threat Model Template
# 3. Drag Azure services onto the canvas
# 4. Draw data flows and trust boundaries
# 5. TMT auto-generates STRIDE threats for each element
# 6. Review and mark mitigations
# 7. Generate report (PDF/HTML)

# Alternative: OWASP Threat Dragon (cross-platform, open source)
npm install -g threat-dragon
threat-dragon
```

## PASTA framework for Azure

```
PASTA (Process for Attack Simulation and Threat Analysis) on Azure
═══════════════════════════════════════════════════════════════════

Stage 1: Define Business Objectives
  → What business processes does this Azure workload support?
  → What are the compliance requirements (GDPR, PCI DSS, HIPAA)?
  → What is the financial impact of a breach?

Stage 2: Define Technical Scope
  → Azure services in scope: [App Service, SQL, Key Vault, Front Door]
  → Azure subscriptions and resource groups
  → External dependencies and third-party integrations

Stage 3: Application Decomposition
  → Data flow diagrams (DFDs)
  → Trust boundaries (mapped to Azure network segments)
  → Entra ID authentication flows

Stage 4: Threat Analysis
  → Map MITRE ATT&CK for Cloud (Azure)
  → Microsoft Secure Score gap analysis
  → Defender for Cloud recommendations

Stage 5: Vulnerability and Weakness Analysis
  → Defender for Cloud vulnerability assessment (Qualys/Rapid7)
  → Azure Security Benchmark gaps
  → Penetration test findings

Stage 6: Attack Modeling
  → Attack trees for top 3 risks
  → Azure-specific attack paths (lateral movement, privilege escalation)
  → Red team exercise scope

Stage 7: Risk and Impact Analysis
  → CVSS scoring for identified vulnerabilities
  → Business impact analysis
  → Remediation prioritization by risk level
```

## Threat modeling checklist

```
THREAT MODELING PROGRAM CHECKLIST
═══════════════════════════════════

Process
  ☐ Threat models created for all new Azure architectures
  ☐ Threat model updated per release (if DFD changes)
  ☐ Annual full architecture review scheduled
  ☐ Threat model reviews part of design review gate
  ☐ Security champions trained in STRIDE + Microsoft TMT

Azure-Specific
  ☐ Microsoft Threat Modeling Tool with Azure stencils
  ☐ MITRE ATT&CK for Cloud mapped to architecture
  ☐ Azure Security Benchmark used as control library
  ☐ Defender for Cloud recommendations inform threat model
  ☐ Penetration test scope derived from threat model

Output
  ☐ Threat model report published and version controlled
  ☐ Open risks tracked in security backlog
  ☐ Mitigations linked to Azure security controls
  ☐ Risk acceptance documented with business owner sign-off
  ☐ Threat model metrics reported to CISO quarterly
```
