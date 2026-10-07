# Project 3: CI/CD Security Pipeline on Azure DevOps & GitHub Actions

## Overview

This project sets up automated security scanning in Azure DevOps and GitHub Actions pipelines. It integrates secret detection, static analysis, container image vulnerability checks, and Infrastructure as Code validation before workloads deploy to Azure environments.

## Pipeline architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                   SECURE AZURE DEVOPS / GITHUB ACTIONS PIPELINE                 │
└─────────────────────────────────────────────────────────────────────────────────┘

 Developer                                                              Production
    │                                                                       │
    ▼                                                                       │
┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│  Code  │──▶│  Build │──▶│Security│──▶│  Test  │──▶│ Deploy │──▶│  Prod  │
│ Commit │   │        │   │ Checks │   │        │   │Staging │   │        │
└────────┘   └────────┘   └────────┘   └────────┘   └────────┘   └────────┘
    │            │            │            │            │            │
    ▼            ▼            ▼            ▼            ▼            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                     AZURE SECURITY GATES AT EACH STAGE                     │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Pre-Commit    Build           Security          Deploy         Prod       │
│  ──────────    ─────           ────────          ──────         ────       │
│  • Secrets     • SAST          • Bicep/TF scan   • Approval     • WAF     │
│    scanning    • Dep scan      • Azure Policy    • Canary       • IDPS    │
│  • Gitleaks    • Container     • Compliance      • Deployment   • Sentinel │
│  • Linting       scan (Trivy)  • SBOM check        health       • Alerts  │
│                • Defender                                                  │
│                  for DevOps                                                │
└────────────────────────────────────────────────────────────────────────────┘
```

## Pipeline security tooling

| Tool | Purpose |
|---|---|
| GitHub Advanced Security / Defender for DevOps | SAST |
| Microsoft Defender for Containers | Container scanning |
| Azure Policy + Compliance | Policy as code |
| PSRule for Azure / Checkov | IaC scanning |
| GitHub Dependabot | Dependency scanning |
| Azure Key Vault + Managed Identity | Secrets retrieval |
| Workload Identity Federation | Keyless pipeline authentication |
| Azure DevOps Environment Approval | Manual deployment gates |


## Implementation 1: GitHub Actions with Azure OIDC

### `.github/workflows/secure-pipeline.yml`

```yaml
name: Secure Azure CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  id-token: write      # Required for OIDC (Workload Identity Federation)
  contents: read
  security-events: write  # Required for SARIF upload
  pull-requests: write

env:
  AZURE_SUBSCRIPTION_ID: ${{ vars.AZURE_SUBSCRIPTION_ID }}
  AZURE_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
  RESOURCE_GROUP: rg-app-${{ github.ref_name }}

jobs:
  # ─────────────────────────────────────
  # STAGE 1: Pre-Commit Security Checks
  # ─────────────────────────────────────
  secrets-scan:
    name: 🔍 Secrets Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for secret scanning

      - name: Scan for secrets with Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Microsoft Security DevOps — Credential Scanner
        uses: microsoft/security-devops-action@v1
        id: msdo
        with:
          tools: credscan,bandit,eslint,templateanalyzer

      - name: Upload MSDO SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.msdo.outputs.sarifFile }}

  # ─────────────────────────────────────
  # STAGE 2: SAST & Dependency Scanning
  # ─────────────────────────────────────
  code-security:
    name: 🔐 Code Security Analysis
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python,javascript,typescript

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:python"

      - name: Dependency Review (on PRs)
        if: github.event_name == 'pull_request'
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          deny-licenses: GPL-2.0, GPL-3.0

  # ─────────────────────────────────────
  # STAGE 3: Container Security
  # ─────────────────────────────────────
  container-security:
    name: 🐳 Container Scanning
    runs-on: ubuntu-latest
    needs: code-security
    steps:
      - uses: actions/checkout@v4

      - name: Build container image
        run: docker build -t app:${{ github.sha }} .

      - name: Scan container with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Fail on CRITICAL/HIGH

      - name: Upload Trivy SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

  # ─────────────────────────────────────
  # STAGE 4: IaC Security Scanning
  # ─────────────────────────────────────
  iac-security:
    name: 🏗️ IaC Security Scan
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v4

      - name: Scan Bicep/ARM with PSRule for Azure
        uses: microsoft/psrule-azure@latest
        with:
          modules: PSRule.Rules.Azure
          inputPath: './infrastructure/**/*.bicep'

      - name: Scan Terraform with Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: ./infrastructure/terraform
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

      - name: Upload Checkov SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov.sarif

      - name: Scan with KICS (Kubernetes + IaC)
        uses: checkmarx/kics-github-action@v1
        with:
          path: './infrastructure'
          output_formats: 'sarif'

  # ─────────────────────────────────────
  # STAGE 5: Build & Push to ACR
  # ─────────────────────────────────────
  build-push:
    name: 🏗️ Build & Push to ACR
    runs-on: ubuntu-latest
    needs: [container-security, iac-security]
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
    steps:
      - uses: actions/checkout@v4

      # Keyless auth — No passwords stored anywhere
      - name: Azure Login (OIDC — No Secrets!)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Login to Azure Container Registry
        run: az acr login --name ${{ vars.ACR_NAME }}

      - name: Extract metadata for Docker
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ vars.ACR_NAME }}.azurecr.io/app

      - name: Build and push to ACR
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  # ─────────────────────────────────────
  # STAGE 6: Deploy to Staging (with approval gate)
  # ─────────────────────────────────────
  deploy-staging:
    name: 🚀 Deploy to Staging
    runs-on: ubuntu-latest
    needs: build-push
    environment: staging  # Environment protection rules — requires approval
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy Bicep to Staging
        uses: azure/arm-deploy@v2
        with:
          resourceGroupName: rg-app-staging
          template: ./infrastructure/main.bicep
          parameters: environment=staging imageTag=${{ needs.build-push.outputs.image-tag }}

      - name: Run DAST with OWASP ZAP
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: 'https://staging.myapp.example.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

  # ─────────────────────────────────────
  # STAGE 7: Deploy to Production (manual approval required)
  # ─────────────────────────────────────
  deploy-prod:
    name: 🏭 Deploy to Production
    runs-on: ubuntu-latest
    needs: deploy-staging
    environment: production  # Requires 2 approvers + 10-minute delay
    steps:
      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy to Production (Canary)
        uses: azure/arm-deploy@v2
        with:
          resourceGroupName: rg-app-prod
          template: ./infrastructure/main.bicep
          parameters: environment=prod imageTag=${{ needs.build-push.outputs.image-tag }}
```

## Implementation 2: Azure DevOps pipeline (`azure-pipelines.yml`)

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: azure-security-vars  # Azure DevOps Variable Group (secrets from Key Vault)
  - name: imageRepository
    value: 'myapp'
  - name: containerRegistry
    value: '$(ACR_NAME).azurecr.io'

stages:
  # ─────────────────────────────────────────
  - stage: SecurityScan
    displayName: '🔍 Security Scanning'
    jobs:
      - job: SecretsScan
        displayName: 'Secrets & SAST Scan'
        steps:
          - task: MicrosoftSecurityDevOps@1
            displayName: 'Microsoft Security DevOps'
            inputs:
              categories: 'secrets,code,IaC'

          - task: PublishTestResults@2
            condition: always()
            inputs:
              testResultsFormat: 'JUnit'
              testResultsFiles: '**/*-results.xml'

      - job: ContainerScan
        displayName: 'Container Image Scan'
        dependsOn: SecretsScan
        steps:
          - task: Docker@2
            inputs:
              command: 'build'
              Dockerfile: 'Dockerfile'
              tags: '$(Build.BuildId)'

          - task: trivy@1
            inputs:
              image: '$(containerRegistry)/$(imageRepository):$(Build.BuildId)'
              exitCode: '1'
              severity: 'CRITICAL,HIGH'

  # ─────────────────────────────────────────
  - stage: Build
    displayName: '🏗️ Build & Push'
    dependsOn: SecurityScan
    jobs:
      - job: BuildPush
        displayName: 'Build and Push to ACR'
        steps:
          - task: AzureCLI@2
            displayName: 'Login to ACR via Managed Identity'
            inputs:
              azureSubscription: 'Azure-Service-Connection'
              scriptType: 'bash'
              scriptLocation: 'inlineScript'
              inlineScript: |
                az acr login --name $(ACR_NAME)
                docker push $(containerRegistry)/$(imageRepository):$(Build.BuildId)

  # ─────────────────────────────────────────
  - stage: DeployStaging
    displayName: '🚀 Deploy to Staging'
    dependsOn: Build
    environment: 'staging'  # Requires environment approval
    jobs:
      - deployment: DeployStaging
        displayName: 'Deploy to Staging'
        environment: 'staging'
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureCLI@2
                  displayName: 'Deploy Bicep'
                  inputs:
                    azureSubscription: 'Azure-Service-Connection'
                    scriptType: 'bash'
                    scriptLocation: 'inlineScript'
                    inlineScript: |
                      az deployment group create \
                        --resource-group rg-app-staging \
                        --template-file infrastructure/main.bicep \
                        --parameters environment=staging \
                        --parameters imageTag=$(Build.BuildId)

  # ─────────────────────────────────────────
  - stage: DeployProd
    displayName: '🏭 Deploy to Production'
    dependsOn: DeployStaging
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployProd
        environment: 'production'  # Requires 2 approvers
        strategy:
          canary:
            increments: [10, 50, 100]  # Canary rollout: 10% → 50% → 100%
            deploy:
              steps:
                - task: AzureCLI@2
                  inputs:
                    azureSubscription: 'Azure-Service-Connection'
                    scriptType: 'bash'
                    scriptLocation: 'inlineScript'
                    inlineScript: |
                      az deployment group create \
                        --resource-group rg-app-prod \
                        --template-file infrastructure/main.bicep \
                        --parameters environment=prod
```

## Key Vault integration in pipelines

```bash
# Avoid hardcoding secrets in pipeline variables
# In Azure DevOps: Link Variable Group to Key Vault
# In GitHub Actions: Use azure/get-keyvault-secrets action

# GitHub Actions — Fetch secrets from Key Vault (no stored secrets)
- name: Get secrets from Key Vault
  uses: azure/get-keyvault-secrets@v1
  with:
    keyvault: kv-myapp-prod
    secrets: 'db-password, api-key, jwt-secret'
  id: keyvault-secrets
  env:
    AZURE_CREDENTIALS: ${{ secrets.AZURE_CREDENTIALS }}  # Only service principal for KV access
```

## Microsoft Defender for DevOps

```yaml
# Enable Defender for DevOps in your GitHub org or Azure DevOps org
# This provides:
# - Continuous security posture monitoring
# - Pull Request annotations for security findings
# - Unified view in Microsoft Defender for Cloud

- name: Microsoft Security DevOps
  uses: microsoft/security-devops-action@v1
  id: msdo
  with:
    tools: |
      templateanalyzer    # ARM/Bicep scanning
      terrascan           # Terraform scanning
      trivy               # Container scanning
      bandit              # Python SAST
      eslint              # JavaScript SAST
      checkov             # Multi-IaC scanning
    publish: true  # Publish results to Defender for Cloud
```

## Security checklist

```
AZURE DEVOPS / GITHUB ACTIONS SECURITY
════════════════════════════════════════

Pipeline Authentication
  ☐ Use Workload Identity Federation (OIDC) — zero stored credentials
  ☐ No service principal secrets in pipeline variables
  ☐ All secrets referenced from Azure Key Vault
  ☐ Restrict Service Connection scope to specific resource groups
  ☐ Use Managed Identity for self-hosted agents

Security Scanning
  ☐ Secrets scanning enabled (GitHub Advanced Security / Gitleaks)
  ☐ SAST with CodeQL or Defender for DevOps
  ☐ Container scanning with Trivy at build time
  ☐ IaC scanning with PSRule for Azure + Checkov
  ☐ Dependency scanning with GitHub Dependabot
  ☐ DAST on staging environment (OWASP ZAP)

Deployment Controls
  ☐ Manual approval gates for staging and production
  ☐ Production requires 2 approvers
  ☐ Canary/Blue-Green deployment strategy
  ☐ Automatic rollback on failed health checks
  ☐ Branch protection rules (no direct push to main)

Supply Chain Security
  ☐ SBOM generated and stored per release
  ☐ Container images signed (Notary v2 / cosign)
  ☐ Pin actions to full commit SHA (not tags)
  ☐ Dependabot for pipeline action updates
```
