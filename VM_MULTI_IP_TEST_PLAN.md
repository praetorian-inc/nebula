# VM Multi-IP Subnet NSG Fix - E2E Test Plan

**Issue**: GitHub #202 / PS-451
**Fix**: Extract subnet ID per IP config instead of always using [0]
**Subscription**: 55669d9a-8cb4-4761-b7eb-0cc2d10b3051

---

## Test Infrastructure

### Test VM 1: Multi-IP, Public IP in Second Config (The Bug Case)
**Purpose**: Verify fix correctly uses subnet-B NSG instead of subnet-A NSG

```
Resource Group: rg-vm-test-multi-ip
Location: eastus

VNet: vnet-test-multi-ip (10.1.0.0/16)
  ├─ Subnet-A: subnet-a (10.1.1.0/24)
  │    └─ NSG: nsg-subnet-a
  │         └─ Inbound Rule: Allow port 443 from Internet
  └─ Subnet-B: subnet-b (10.1.2.0/24)
       └─ NSG: nsg-subnet-b
            └─ Inbound Rule: Allow port 22 from Internet

VM: vm-test-case-1
  └─ NIC: nic-test-case-1
       ├─ ipConfig1 (primary): subnet-A, private IP only (10.1.1.4)
       └─ ipConfig2 (secondary): subnet-B, public IP + private IP (10.1.2.4)

Expected BEFORE Fix:
  - Query uses subnet-A NSG (from [0])
  - Shows openPorts: ["443"]
  - ❌ WRONG: Public IP is in subnet-B, not subnet-A

Expected AFTER Fix:
  - Query uses subnet-B NSG (from ipconfig2)
  - Shows openPorts: ["22"]
  - ✅ CORRECT: Public IP is in subnet-B with port 22 open
```

### Test VM 2: Multi-IP, Both Have Public IPs (Coverage Case)
**Purpose**: Verify both IPs get correct subnet NSG rules

```
VNet: vnet-test-multi-ip (same)
  ├─ Subnet-C: subnet-c (10.1.3.0/24)
  │    └─ NSG: nsg-subnet-c
  │         └─ Inbound Rule: Allow port 80 from Internet
  └─ Subnet-D: subnet-d (10.1.4.0/24)
       └─ NSG: nsg-subnet-d
            └─ Inbound Rule: Allow port 8080 from Internet

VM: vm-test-case-2
  └─ NIC: nic-test-case-2
       ├─ ipConfig1 (primary): subnet-C, public IP + private IP (10.1.3.4)
       └─ ipConfig2 (secondary): subnet-D, public IP + private IP (10.1.4.4)

Expected BEFORE Fix:
  - Both IPs show subnet-C NSG rules
  - subnetIds: ["subnet-C"] (missing subnet-D)
  - ❌ WRONG: Missing subnet-D NSG in analysis

Expected AFTER Fix:
  - Each IP gets correct subnet NSG
  - subnetIds: ["subnet-C", "subnet-D"]
  - ✅ CORRECT: Both subnets included in NSG analysis
```

### Test VM 3: Single IP (Baseline/Control)
**Purpose**: Verify no regression for common single-IP case

```
VNet: vnet-test-multi-ip (same)
  └─ Subnet-E: subnet-e (10.1.5.0/24)
       └─ NSG: nsg-subnet-e
            └─ Inbound Rule: Allow port 3389 from Internet

VM: vm-test-case-3
  └─ NIC: nic-test-case-3
       └─ ipConfig1 (primary): subnet-E, public IP + private IP (10.1.5.4)

Expected BEFORE & AFTER Fix:
  - Shows openPorts: ["3389"]
  - ✅ SAME: No change in behavior for single-IP configs
```

---

## Test Execution Steps

### Phase 1: Deploy Infrastructure
1. Create resource group
2. Create VNet with 5 subnets (A, B, C, D, E)
3. Create 5 NSGs with different rules
4. Create 5 public IPs
5. Create 3 NICs with multi-IP configurations
6. Create 3 VMs

### Phase 2: Test BEFORE Fix (Baseline)
1. Checkout commit before fix
2. Build nebula binary
3. Run ARG scan
4. Document findings for each VM
5. Verify bug exists (VM1 shows wrong ports, VM2 missing subnet)

### Phase 3: Test AFTER Fix
1. Checkout commit with fix
2. Build nebula binary
3. Run ARG scan
4. Document findings for each VM
5. Verify fix works (VM1 shows correct ports, VM2 includes both subnets)

### Phase 4: Cleanup
1. Delete test VMs
2. Delete test NICs, PIPs, NSGs
3. Delete test VNet
4. Delete resource group

---

## Success Criteria

✅ **VM Test Case 1**: Public IP in second IP config shows subnet-B NSG rules (port 22), not subnet-A (port 443)

✅ **VM Test Case 2**: Both public IPs included in analysis with correct subnet NSGs

✅ **VM Test Case 3**: Single-IP VM behavior unchanged (no regression)

✅ **No False Positives**: No VMs incorrectly flagged

✅ **No False Negatives**: All VMs with public IPs detected

---

## Cost & Timing Estimate

- **Resources**: 3 VMs (B1s SKU)
- **Duration**: ~30 minutes testing + cleanup
- **Cost**: ~$0.50 (assuming quick cleanup)
