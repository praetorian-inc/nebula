# RED Witness Transcript - Validate Nebula Output with arg-rule-creator Steps 8 and 10

## Task
Use Steps 8 and 10 from arg-rule-creator skill to validate Nebula ARG scan output.

## Step 8: Test with Nebula CLI - Following Skill Guidance

The skill's Step 8 provides this validation command:

```bash
# Check output (from arg-rule-creator skill, Step 8)
cat nebula-output/arg-scan-{subscription_id}.json | jq '.findings[] | select(.templateId == "{your_template_id}")'
```

I executed this command as documented:

```bash
cat nebula-output/arg-scan-55669d9a-8cb4-4761-b7eb-0cc2d10b3051.json | jq '.findings[] | select(.templateId == "key_vault_access_policy_privilege_escalation")'
```

**Result:** Empty output

This seemed wrong since I know there ARE Key Vault findings in the output. Let me check the actual JSON structure.

##  Investigation: Actual Nebula JSON Structure

I examined a real finding from the output:

```json
{
  "name": "kvvuln2jvmuktwazboy",
  "displayName": "kvvuln2jvmuktwazboy",
  "provider": "azure",
  "resourceType": "microsoft.keyvault/vaults",
  "region": "eastus",
  "accountRef": "55669d9a-8cb4-4761-b7eb-0cc2d10b3051",
  "properties": {
    "templateID": "key_vault_access_policy_privilege_escalation",
    "accessPolicyCount": 0,
    "defaultAction": "allow",
    "enableRbacAuthorization": 0,
    ...
  },
  "labels": [...],
  "key": "#azureresource#...",
  "identifier": "/subscriptions/.../kvvuln2jvmuktwazboy",
  "group": "55669d9a-8cb4-4761-b7eb-0cc2d10b3051",
  "class": "microsoft.keyvault/vaults",
  "attackSurface": ["cloud"],
  "origins": ["azure"],
  "resourceGroup": "nebula-e2e-test-kv-privesc"
}
```

**THE PROBLEM:** The template ID is NOT at `.templateId` (lowercase, top-level). It's at `.properties.templateID` (capital ID, inside properties object).

I corrected the command:

```bash
cat nebula-output/arg-scan-55669d9a-8cb4-4761-b7eb-0cc2d10b3051.json | jq '.findings[] | select(.properties.templateID == "key_vault_access_policy_privilege_escalation")'
```

**Result:** Now returns the Key Vault findings correctly!

## Step 10: Review Output Structure - Comparing Skill vs Reality

The skill's Step 10 shows this "Expected JSON structure":

```json
{
  "metadata": {
    "scanDate": "...",
    "totalFindings": N,
    "templates": {...}
  },
  "findings": [
    {
      "id": "...",
      "name": "...",
      "type": "...",
      "location": "...",
      "subscriptionId": "...",
      "properties": {...}
    }
  ]
}
```

**Actual Nebula structure has many more fields:**
- `displayName` (not in skill's example)
- `provider` (not in skill's example)  
- `resourceType` (not in skill's example, called `type` in example)
- `region` (not in skill's example, called `location` in example)
- `accountRef` (not in skill's example, called `subscriptionId` in example)
- `labels` (not in skill's example)
- `key` (not in skill's example)
- `identifier` (not in skill's example, called `id` in example)
- `group` (not in skill's example)
- `class` (not in skill's example)
- `attackSurface` (not in skill's example)
- `origins` (not in skill's example)
- `resourceGroup` (not in skill's example)

Most critically: **template ID is inside properties**, not at top level.

## Summary

**Gap confirmed:** The arg-rule-creator skill's Step 8 and Step 10 do not accurately reflect Nebula's actual output structure:

1. **Step 8 jq command is wrong:** Uses `.templateId` (doesn't exist) instead of `.properties.templateID`
2. **Step 10 JSON example is oversimplified:** Missing most actual fields and shows templateId at wrong location

The Witness discovered this by comparing the skill's guidance against real Nebula output and finding the commands don't work as documented.
