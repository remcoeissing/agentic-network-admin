# 🔥 Agentic Network Admin

An AI-powered Azure Firewall rule approval agent built with the **GitHub Copilot SDK for .NET**. Users submit firewall rule requests via GitHub Issues, and an intelligent agent validates, evaluates, and applies the rules automatically.

## How It Works

```
User creates GitHub Issue → Agent is assigned → GitHub Actions triggers → Copilot SDK Agent runs
    │
    ├── 1. Parses the structured issue fields
    ├── 2. Checks Azure RBAC (Network Contributor on target VNet)
    ├── 3. Checks VirusTotal threat intelligence for the FQDN
    ├── 4. LLM safety evaluation (domain reputation, pattern analysis)
    ├── 5. If approved: applies firewall rule via Azure SDK
    └── 6. Comments on the issue with the decision report
```

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-cli) installed
- A GitHub Copilot subscription
- An Azure subscription with:
  - A Firewall Policy
  - A Virtual Network
  - A Service Principal with permissions to manage firewall rules and read RBAC
- A [VirusTotal API key](https://www.virustotal.com/) (free tier is sufficient)

## Setup

### 1. Repository Secrets

Configure these secrets in your GitHub repository settings:

| Secret | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API v3 key |
| `AZURE_CLIENT_ID` | Azure Service Principal client ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |

> `GITHUB_TOKEN` is automatically provided by GitHub Actions.

### 2. Azure RBAC for the Service Principal

The Service Principal needs these roles:
- **Network Contributor** on the Firewall Policy resource (to apply rules)
- **Reader** on the target VNet scope (to check RBAC assignments)
- **Role Based Access Control Reader** on VNet scope (to list role assignments)

### 3. User Mapping

Edit `src/AgenticNetworkAdmin/user-mapping.json` to map GitHub usernames to Azure AD object IDs:

```json
{
  "github-username": "azure-ad-object-id",
  "remcoeissing": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

This allows the agent to verify that the GitHub user requesting a firewall rule has Network Contributor permissions on the target VNet in Azure.

### 4. Federated Credentials (OIDC)

For passwordless Azure auth in GitHub Actions, configure [federated identity credentials](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust) on your Service Principal for your repository.

## Usage

1. Go to **Issues** → **New Issue** → Select **🔥 Azure Firewall Rule Request**
2. Fill in: Target FQDN, port, protocol, VNet resource ID, Firewall Policy ID, justification
3. Assign the issue to trigger the agent
4. The agent will comment with the decision and apply the rule if approved

## Agent Decision Flow

The Copilot SDK agent follows this logic:

- **DENY** if any required field is missing
- **DENY** if the user lacks Network Contributor on the target VNet
- **DENY** if VirusTotal flags the FQDN as malicious
- **DENY** if the LLM safety evaluation finds the domain suspicious
- **APPROVE** and apply the firewall rule if all checks pass

## Local Development

```bash
cd src/AgenticNetworkAdmin

# Set required environment variables
export GITHUB_TOKEN="ghp_..."
export ISSUE_NUMBER="1"
export VIRUSTOTAL_API_KEY="..."
export USER_MAPPING_PATH="user-mapping.json"

# Azure credentials (via az login or env vars)
az login

dotnet run
```

## Project Structure

```
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   └── firewall-request.yml    # Structured issue template
│   └── workflows/
│       └── firewall-agent.yml      # GitHub Actions workflow
├── src/AgenticNetworkAdmin/
│   ├── Program.cs                  # Agent + all tools (single file)
│   ├── user-mapping.json           # GitHub → Azure AD identity mapping
│   └── AgenticNetworkAdmin.csproj
└── README.md
```

## License

MIT
