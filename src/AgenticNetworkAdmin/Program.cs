using System.ComponentModel;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using DotNetEnv;
using GitHub.Copilot.SDK;
using Microsoft.Extensions.AI;
using Octokit;

// ── Load environment variables from .env file ──────────────────────────────
Env.Load();

// ── Configuration from environment ──────────────────────────────────────────
var repo = Environment.GetEnvironmentVariable("GITHUB_REPOSITORY") ?? "remcoeissing/agentic-network-admin";
var repoParts = repo.Split('/');
var owner = repoParts[0];
var repoName = repoParts[1];
var issueNumber = int.Parse(Environment.GetEnvironmentVariable("ISSUE_NUMBER")
    ?? throw new InvalidOperationException("ISSUE_NUMBER environment variable is required"));
var githubToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN")
    ?? throw new InvalidOperationException("GITHUB_TOKEN environment variable is required");
var virusTotalApiKey = Environment.GetEnvironmentVariable("VIRUSTOTAL_API_KEY")
    ?? throw new InvalidOperationException("VIRUSTOTAL_API_KEY environment variable is required");
var userMappingPath = Environment.GetEnvironmentVariable("USER_MAPPING_PATH") ?? "user-mapping.json";

// ── Shared clients ──────────────────────────────────────────────────────────
var github = new GitHubClient(new ProductHeaderValue("AgenticNetworkAdmin"))
{
    Credentials = new Credentials(githubToken)
};
var httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Add("x-apikey", virusTotalApiKey);
httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AgenticNetworkAdmin/1.0");

var azureCredential = new DefaultAzureCredential();
var armClient = new ArmClient(azureCredential);

// ── Helper: parse issue body fields ─────────────────────────────────────────
static string ExtractField(string body, string heading)
{
    var pattern = $@"### {Regex.Escape(heading)}\s*\n\s*(.+?)(?=\n###|\z)";
    var match = Regex.Match(body, pattern, RegexOptions.Singleline);
    return match.Success ? match.Groups[1].Value.Trim() : "";
}

// ── Tool 1: Get issue details ───────────────────────────────────────────────
var getIssueDetails = AIFunctionFactory.Create(
    async () =>
    {
        var issue = await github.Issue.Get(owner, repoName, issueNumber);
        var body = issue.Body ?? "";
        return new
        {
            issue.Number,
            issue.Title,
            Author = issue.User.Login,
            Fqdn = ExtractField(body, "Target FQDN"),
            Port = ExtractField(body, "Destination Port"),
            Protocol = ExtractField(body, "Protocol"),
            VnetResourceId = ExtractField(body, "Source Virtual Network Resource ID"),
            FirewallPolicyId = ExtractField(body, "Firewall Policy Resource ID"),
            Justification = ExtractField(body, "Business Justification")
        };
    },
    "get_issue_details",
    "Fetches and parses the GitHub firewall request issue. Returns structured fields: FQDN, port, protocol, VNet resource ID, firewall policy ID, justification, and the requesting user.");

// ── Tool 2: Check VirusTotal ────────────────────────────────────────────────
var checkVirusTotal = AIFunctionFactory.Create(
    async ([Description("The FQDN to check against VirusTotal threat intelligence")] string fqdn) =>
    {
        var cleanFqdn = fqdn.TrimStart('*', '.');
        var response = await httpClient.GetAsync($"https://www.virustotal.com/api/v3/domains/{cleanFqdn}");
        if (!response.IsSuccessStatusCode)
        {
            return new { IsMalicious = false, Error = $"VirusTotal returned {response.StatusCode}", Details = "" };
        }

        var json = await response.Content.ReadFromJsonAsync<JsonNode>();
        var stats = json?["data"]?["attributes"]?["last_analysis_stats"];
        var malicious = stats?["malicious"]?.GetValue<int>() ?? 0;
        var suspicious = stats?["suspicious"]?.GetValue<int>() ?? 0;
        var harmless = stats?["harmless"]?.GetValue<int>() ?? 0;
        var undetected = stats?["undetected"]?.GetValue<int>() ?? 0;
        var reputation = json?["data"]?["attributes"]?["reputation"]?.GetValue<int>() ?? 0;

        return new
        {
            IsMalicious = malicious > 0 || suspicious > 2,
            Error = "",
            Details = $"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}, Reputation score: {reputation}"
        };
    },
    "check_virustotal",
    "Checks an FQDN against VirusTotal threat intelligence. Returns whether the domain is flagged as malicious and detailed analysis stats.");

// ── Tool 3: Check Azure RBAC ────────────────────────────────────────────────
var checkAzureRbac = AIFunctionFactory.Create(
    async (
        [Description("The GitHub username of the requester")] string githubUsername,
        [Description("The full Azure resource ID of the target Virtual Network")] string vnetResourceId) =>
    {
        // Load GitHub-to-Azure identity mapping
        if (!File.Exists(userMappingPath))
            return new { HasPermission = false, Reason = $"User mapping file not found at {userMappingPath}" };

        var mappingJson = await File.ReadAllTextAsync(userMappingPath);
        var mapping = JsonSerializer.Deserialize<Dictionary<string, string>>(mappingJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (mapping == null || !mapping.TryGetValue(githubUsername, out var azureObjectId))
            return new { HasPermission = false, Reason = $"No Azure identity mapping found for GitHub user '{githubUsername}'" };

        // Check role assignments on the VNet scope
        var vnetIdentifier = new Azure.Core.ResourceIdentifier(vnetResourceId);
        var roleAssignments = armClient.GetRoleAssignments(vnetIdentifier);

        // Network Contributor role definition ID (built-in)
        const string networkContributorRoleId = "4d97b98b-1d4f-4787-a291-c67834d212e7";

        await foreach (var assignment in roleAssignments)
        {
            if (assignment.Data.PrincipalId.ToString() == azureObjectId &&
                assignment.Data.RoleDefinitionId.Name == networkContributorRoleId)
            {
                return new { HasPermission = true, Reason = "User has Network Contributor role on the VNet" };
            }
        }

        return new { HasPermission = false, Reason = $"User '{githubUsername}' (Azure OID: {azureObjectId}) does not have Network Contributor role on {vnetResourceId}" };
    },
    "check_azure_rbac",
    "Checks whether the GitHub user has Network Contributor RBAC permissions on the specified Azure Virtual Network. Uses a GitHub-to-Azure identity mapping file.");

// ── Tool 4: Apply firewall rule ─────────────────────────────────────────────
var applyFirewallRule = AIFunctionFactory.Create(
    async (
        [Description("The full Azure resource ID of the Firewall Policy")] string firewallPolicyId,
        [Description("The target FQDN for the rule (e.g., api.example.com)")] string fqdn,
        [Description("The destination port (e.g., 443)")] string port,
        [Description("The protocol (HTTPS, HTTP, or MSSQL)")] string protocol,
        [Description("A short rule name derived from the issue")] string ruleName) =>
    {
        try
        {
            var policyResourceId = new Azure.Core.ResourceIdentifier(firewallPolicyId);
            var policyResource = armClient.GetFirewallPolicyResource(policyResourceId);
            var policy = await policyResource.GetAsync();

            // Get or create the rule collection group
            var rcgCollection = policyResource.GetFirewallPolicyRuleCollectionGroups();
            FirewallPolicyRuleCollectionGroupResource rcg;
            try
            {
                rcg = await rcgCollection.GetAsync("github-managed-rules");
            }
            catch
            {
                // Create the rule collection group if it doesn't exist
                var rcgData = new FirewallPolicyRuleCollectionGroupData
                {
                    Priority = 500
                };
                var rcgOp = await rcgCollection.CreateOrUpdateAsync(Azure.WaitUntil.Completed, "github-managed-rules", rcgData);
                rcg = rcgOp.Value;
            }

            // Build the application rule
            var appRule = new ApplicationRule
            {
                Name = ruleName,
                Description = $"Auto-approved via GitHub Issue #{issueNumber}"
            };
            appRule.TargetFqdns.Add(fqdn);
            appRule.Protocols.Add(new FirewallPolicyRuleApplicationProtocol
            {
                ProtocolType = protocol.ToUpper() == "HTTP"
                    ? FirewallPolicyRuleApplicationProtocolType.Http
                    : FirewallPolicyRuleApplicationProtocolType.Https,
                Port = int.Parse(port)
            });
            appRule.SourceAddresses.Add("*");

            // Add to a filter rule collection within the group
            var rcgData2 = rcg.Data;
            var existingCollection = rcgData2.RuleCollections
                .OfType<FirewallPolicyFilterRuleCollectionInfo>()
                .FirstOrDefault(rc => rc.Name == "github-app-rules");

            if (existingCollection != null)
            {
                existingCollection.Rules.Add(appRule);
            }
            else
            {
                var newCollection = new FirewallPolicyFilterRuleCollectionInfo
                {
                    Name = "github-app-rules",
                    Priority = 1000,
                    ActionType = FirewallPolicyFilterRuleCollectionActionType.Allow
                };
                newCollection.Rules.Add(appRule);
                rcgData2.RuleCollections.Add(newCollection);
            }

            await rcg.UpdateAsync(Azure.WaitUntil.Completed, rcgData2);
            return new { Success = true, Message = $"Firewall rule '{ruleName}' applied successfully for {fqdn}:{port}/{protocol}" };
        }
        catch (Exception ex)
        {
            return new { Success = false, Message = $"Failed to apply firewall rule: {ex.Message}" };
        }
    },
    "apply_firewall_rule",
    "Applies an application rule to an Azure Firewall Policy. Creates a rule collection group named 'github-managed-rules' if it doesn't exist.");

// ── Tool 5: Comment on issue ────────────────────────────────────────────────
var commentOnIssue = AIFunctionFactory.Create(
    async (
        [Description("The markdown-formatted comment body to post")] string comment,
        [Description("The label to apply: 'approved' or 'denied'")] string label) =>
    {
        await github.Issue.Comment.Create(owner, repoName, issueNumber, comment);

        // Apply the label
        var labelName = label == "approved" ? "firewall-approved" : "firewall-denied";
        await github.Issue.Labels.AddToIssue(owner, repoName, issueNumber, [labelName]);

        // Remove the pending label
        try { await github.Issue.Labels.RemoveFromIssue(owner, repoName, issueNumber, "pending-review"); }
        catch { /* label may not exist */ }

        // Close the issue if approved
        if (label == "approved")
        {
            await github.Issue.Update(owner, repoName, issueNumber, new IssueUpdate { State = ItemState.Closed });
        }

        return new { Success = true, Message = $"Comment posted and issue labeled as '{labelName}'" };
    },
    "comment_on_issue",
    "Posts a comment on the GitHub issue with the decision and applies a label (firewall-approved or firewall-denied). Closes the issue if approved.");

// ── System prompt ───────────────────────────────────────────────────────────
var systemPrompt = """
You are an Azure Firewall Rule Approval Agent running in a fully autonomous CI/CD pipeline.
You MUST NOT ask for user input or clarification. You MUST make all decisions yourself.
You have exactly 5 tools available — use ONLY those tools. Do not attempt to use any other tools.

CRITICAL RULES:
- NEVER ask the user for input. You are running unattended in GitHub Actions.
- If information is missing or ambiguous, DENY the request and explain what was missing in your issue comment.
- If you are unsure whether a domain is safe, DENY the request and explain your concerns.
- Always complete the workflow by calling `comment_on_issue` as the final step.
- Do not attempt to read files, browse the web, or run shell commands. Only use the 5 tools provided.

Follow this workflow strictly:

1. **Fetch the issue** using `get_issue_details` to get the request fields.
2. **Validate the request** — ensure all required fields (FQDN, port, protocol, VNet resource ID, firewall policy ID) are present and well-formed. If any are missing or invalid, DENY with an explanation.
3. **Check RBAC permissions** using `check_azure_rbac` with the issue author's GitHub username and the VNet resource ID. If the user lacks permissions, DENY the request.
4. **Check VirusTotal** using `check_virustotal` with the requested FQDN. If the FQDN is flagged as malicious, DENY immediately.
5. **Safety evaluation** — Even if VirusTotal didn't flag the FQDN, evaluate whether it looks safe. Consider:
   - Is it a well-known, reputable domain?
   - Does the domain pattern look suspicious (e.g., random characters, known phishing patterns)?
   - Does the justification make sense for the requested domain?
   - Is the port/protocol combination reasonable?
   If you have any doubt about the safety of the FQDN, DENY with your reasoning.
6. **If all checks pass**, use `apply_firewall_rule` to create the rule, then use `comment_on_issue` with label "approved" and a summary of what was applied.
7. **If any check fails**, use `comment_on_issue` with label "denied" and a clear explanation of why.

Format your issue comment as a professional report with these sections:
- **Decision**: ✅ Approved or ❌ Denied
- **Request Summary**: FQDN, port, protocol
- **Checks Performed**: RBAC, VirusTotal, Safety evaluation results
- **Reasoning**: Your analysis
- **Action Taken**: What was applied (if approved) or next steps (if denied)
""";

// ── Run the agent ───────────────────────────────────────────────────────────
Console.WriteLine($"🔥 Processing firewall request from issue #{issueNumber}...");

Console.WriteLine("📡 Creating Copilot client...");
await using var client = new GitHub.Copilot.SDK.CopilotClient(new GitHub.Copilot.SDK.CopilotClientOptions
{
    GithubToken = githubToken
});

Console.WriteLine("📡 Starting Copilot client...");
await client.StartAsync();
Console.WriteLine("✅ Copilot client started");

Console.WriteLine("📡 Creating session...");
await using var session = await client.CreateSessionAsync(new SessionConfig
{
    Model = "gpt-4.1",
    SystemMessage = new SystemMessageConfig
    {
        Mode = SystemMessageMode.Replace,
        Content = systemPrompt
    },
    Tools = [getIssueDetails, checkVirusTotal, checkAzureRbac, applyFirewallRule, commentOnIssue],
    AvailableTools = new List<string>()
});
Console.WriteLine("✅ Session created");

var done = new TaskCompletionSource();

session.On(evt =>
{
    Console.WriteLine($"📨 Event received: {evt.GetType().Name}");
    switch (evt)
    {
        case AssistantMessageEvent msg:
            Console.WriteLine($"🤖 {msg.Data.Content}");
            break;
        case ToolExecutionStartEvent tool:
            Console.WriteLine($"🔧 Calling tool: {tool.Data.ToolName}");
            break;
        case ToolExecutionCompleteEvent tool:
            Console.WriteLine($"✅ Tool complete");
            break;
        case SessionErrorEvent err:
            Console.Error.WriteLine($"❌ Error: {err.Data.Message}");
            done.TrySetResult();
            break;
        case SessionIdleEvent:
            Console.WriteLine("💤 Session idle - completing");
            done.TrySetResult();
            break;
    }
});

Console.WriteLine("📤 Sending message to session...");
await session.SendAsync(new MessageOptions
{
    Prompt = $"Process the Azure Firewall rule request in issue #{issueNumber}. Follow the workflow in your instructions."
});
Console.WriteLine("✅ Message sent, waiting for completion...");

await done.Task;
Console.WriteLine("🏁 Agent finished processing.");
