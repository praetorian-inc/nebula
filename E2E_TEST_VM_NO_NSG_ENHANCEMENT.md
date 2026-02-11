# E2E Test Report: VM Public Access Enhancement (No-NSG Detection)

**Date**: 2026-02-11
**Issue**: GitHub #202 / PS-451 (Complete Fix)
**Branch**: `elginlee/ps-451-fix-vm-multi-ip-subnet-nsg`
**Template**: `pkg/templates/virtual_machines_public.yaml`

---

## Enhancement Summary

**Problem 1 (Fixed Previously)**: Query used `properties.ipConfigurations[0]` for subnet extraction → Fixed with defensive subnet extraction from ipconfig

**Problem 2 (Fixed Now)**: Query filtered out VMs without NSGs (line 123: `| where nsgCount > 0`) → Most vulnerable VMs (Basic SKU + no NSG) were NOT detected

**Solution**:
1. Keep defensive subnet fix
2. Remove `nsgCount > 0` filter
3. Add Public IP SKU detection (`sku.name` not `properties.sku.name`)
4. Add `hasNSG` field for visibility
5. Handle no-NSG case in `openPorts` with SKU-aware logic
6. Fix `nsgCount` to use `dcountif(nsgId, isnotempty(nsgId))` to exclude empty NSG IDs

---

## Changes Made

### 1. Add Public IP SKU Detection
```kql
# BEFORE:
| project publicIPId = id, publicIP = tostring(properties.ipAddress)

# AFTER:
| project publicIPId = id, publicIP = tostring(properties.ipAddress), publicIPSku = tostring(sku.name)
```

### 2. Carry SKU Through Aggregations
```kql
| summarize
    publicIPs = make_set(publicIP),
    publicIPSkus = make_set(publicIPSku),  # Added
    ...
```

### 3. Fix NSG Counting Logic
```kql
# BEFORE:
nsgCount = dcount(nsgId),  # Counted empty strings as NSGs!

# AFTER:
nsgCount = dcountif(nsgId, isnotempty(nsgId)),  # Only count non-empty NSG IDs
```

### 4. Remove Filter + Add SKU-Aware Logic
```kql
# REMOVED THIS LINE:
| where nsgCount > 0

# ADDED:
| extend hasNSG = (nsgCount > 0)
| extend hasBasicSku = (publicIPSkus has "Basic" or publicIPSkus has "basic")
| extend hasStandardSku = (publicIPSkus has "Standard" or publicIPSkus has "standard")
| extend openPorts = case(
    not(hasNSG) and hasBasicSku, "all (no NSG - Basic SKU default open)",
    not(hasNSG) and hasStandardSku, "none (no NSG - Standard SKU secure by default)",
    not(hasNSG), "all (no NSG)",
    isempty(allOpenPorts) or array_length(allOpenPorts) == 0, "none",
    tostring(allOpenPorts)
)
```

### 5. Enhanced Output Fields
```kql
| project
    name = vmName,
    location = vmLocation,
    publicIPs = tostring(publicIPs),
    privateIPs = tostring(privateIPs),
    openPorts,              # Enhanced with SKU-aware text
    hasNSG,                 # New field
    publicIPSku = tostring(publicIPSkus)  # New field
```

---

## Test Infrastructure

### Created 4 Test VMs in Resource Group: `rg-vm-nsg-test`

| VM | Public IP SKU | NSG Attached | NSG Rules | Purpose |
|----|---------------|--------------|-----------|---------|
| **vm-test-case-1** | Standard | ✅ nsg-with-ports | SSH (22), HTTP (80) | Baseline - existing behavior |
| **vm-test-case-2** | Standard | ✅ nsg-no-ports | None (all deny) | Baseline - existing behavior |
| **vm-test-case-3** | **Basic** | ❌ None | N/A | **NEW - CRITICAL vulnerability** |
| **vm-test-case-4** | Standard | ❌ None | N/A | **NEW - HIGH risk** |

---

## E2E Test Results

### Test Execution Command:
```bash
az graph query -q "$(cat vm-query-final.kql)" --subscriptions 55669d9a-8cb4-4761-b7eb-0cc2d10b3051
```

### Results:

| VM | hasNSG | openPorts | publicIPSku | publicIP | Status |
|----|--------|-----------|-------------|----------|--------|
| **vm-test-case-1** | 1 (true) | `["22","80"]` | Standard | 40.87.20.29 | ✅ PASS |
| **vm-test-case-2** | 1 (true) | `none` | Standard | 20.120.32.76 | ✅ PASS |
| **vm-test-case-3** | 0 (false) | `all (no NSG - Basic SKU default open)` | Basic | 20.102.54.35 | ✅ PASS |
| **vm-test-case-4** | 0 (false) | `none (no NSG - Standard SKU secure by default)` | Standard | 20.127.48.251 | ✅ PASS |

---

## Validation Checklist

### ✅ Test Case 1: VM with NSG and Open Ports (Existing Behavior)
- **Expected**: Detected, hasNSG=true, openPorts shows specific ports
- **Observed**: hasNSG=1, openPorts="[\"22\",\"80\"]", publicIPSku=Standard
- **Result**: ✅ PASS - No regression, existing functionality preserved

### ✅ Test Case 2: VM with NSG but No Open Ports (Existing Behavior)
- **Expected**: Detected, hasNSG=true, openPorts="none"
- **Observed**: hasNSG=1, openPorts="none", publicIPSku=Standard
- **Result**: ✅ PASS - No regression, existing functionality preserved

### ✅ Test Case 3: VM with Basic SKU + No NSG (NEW - Most Vulnerable!)
- **Expected**: Detected, hasNSG=false, openPorts="all (no NSG - Basic SKU default open)"
- **Observed**: hasNSG=0, openPorts="all (no NSG - Basic SKU default open)", publicIPSku=Basic
- **Result**: ✅ PASS - **NOW DETECTS MOST VULNERABLE VMS!**
- **Impact**: Previously MISSED, now correctly flagged as CRITICAL

### ✅ Test Case 4: VM with Standard SKU + No NSG (NEW - High Risk)
- **Expected**: Detected, hasNSG=false, openPorts="none (no NSG - Standard SKU secure by default)"
- **Observed**: hasNSG=0, openPorts="none (no NSG - Standard SKU secure by default)", publicIPSku=Standard
- **Result**: ✅ PASS - **NOW DETECTS HIGH-RISK VMS!**
- **Impact**: Previously MISSED, now correctly flagged for defense-in-depth

---

## Bug Fixes During Development

### Bug 1: Public IP SKU Extraction
- **Issue**: Used `properties.sku.name` → returned empty strings
- **Fix**: Changed to `sku.name` (top-level field)
- **Verification**: All VMs now show correct SKU (Basic vs Standard)

### Bug 2: NSG Count Logic
- **Issue**: `dcount(nsgId)` counted empty strings as NSGs → all VMs showed hasNSG=true
- **Fix**: Changed to `dcountif(nsgId, isnotempty(nsgId))` to exclude empty NSG IDs
- **Verification**: VM3 and VM4 now correctly show hasNSG=0

---

## Impact Analysis

### Before Enhancement:
- ❌ VMs without NSGs: **NOT DETECTED** (filtered out by `| where nsgCount > 0`)
- ❌ Basic SKU + no NSG: **CRITICAL vulnerability MISSED** (all ports exposed to internet)
- ❌ Standard SKU + no NSG: **HIGH risk MISSED** (missing defense-in-depth)

### After Enhancement:
- ✅ VMs without NSGs: **DETECTED** with appropriate severity
- ✅ Basic SKU + no NSG: **Flagged as CRITICAL** ("all ports exposed")
- ✅ Standard SKU + no NSG: **Flagged as HIGH** ("secure by default but add NSG")
- ✅ Existing detections: **PRESERVED** (no regression)

### False Positive/Negative Analysis:
- ✅ **No false positives introduced**: All detections are legitimate security concerns
- ✅ **Reduces false negatives**: Now detects previously missed vulnerable VMs
- ✅ **No regressions**: Existing VM detections work identically

---

## Azure Constraints Learned

### Multi-IP NIC Limitation:
**All IP configurations on a single NIC MUST be in the same subnet.**

- Cannot create NIC with ipConfig1 in subnet-A and ipConfig2 in subnet-B
- Azure enforces: `IpConfigurationsOnSameNicCannotUseDifferentSubnets`
- Impact: Defensive subnet fix (extracting from ipconfig vs [0]) is still valid for robustness, but the bug scenario (different subnets per IP config) cannot exist in practice

### Public IP SKU Behavior:
- **Basic SKU**: Open by default - no NSG means ALL inbound ports exposed
- **Standard SKU**: Secure by default - no NSG still blocks all inbound (requires explicit allow rules)
- **Basic SKU retired**: Sept 30, 2025, but remains operational (unsupported, no SLA)

---

## Updated Template Metadata

### Description:
```
Detects virtual machines with public IPs, evaluating NSG protection status and open ports.
VMs without NSGs are flagged as most vulnerable, especially with Basic SKU public IPs (default open).
```

### Triage Notes:
Added comprehensive guidance on:
- Understanding openPorts field values
- Public IP SKU security behavior (Basic vs Standard)
- Triage priority (CRITICAL → HIGH → LOW)
- Remediation steps for each scenario

---

## Conclusion

✅ **ALL E2E TESTS PASSED**

The enhancement:
1. ✅ Keeps defensive subnet fix (ipconfig vs [0])
2. ✅ Removes `nsgCount > 0` filter (includes all VMs)
3. ✅ Adds Public IP SKU detection (Basic vs Standard)
4. ✅ Adds `hasNSG` field for visibility
5. ✅ Handles no-NSG case with SKU-aware logic
6. ✅ Fixes NSG counting to exclude empty IDs
7. ✅ No regressions in existing functionality
8. ✅ Now detects most vulnerable VMs (Basic SKU + no NSG)

**The template now provides comprehensive coverage of VM public access risks.**

---

## Files Modified

1. `pkg/templates/virtual_machines_public.yaml`:
   - Added Public IP SKU extraction
   - Fixed NSG counting logic
   - Removed nsgCount filter
   - Added hasNSG and publicIPSku output fields
   - Enhanced openPorts with SKU-aware logic
   - Updated description and triage notes

---

## Next Steps

1. ✅ Commit changes
2. ✅ Push branch
3. ✅ Create/update PR referencing GitHub #202
4. Clean up test infrastructure: `az group delete --name rg-vm-nsg-test --yes`
