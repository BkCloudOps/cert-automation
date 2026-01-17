# Certificate Automation Audit Log

This file tracks all automated changes to gateway and certificate configurations.

---

## Automation Run - 2026-01-16 18:38:24 UTC

**Repository:** `BkCloudOps/cert-automation`

**Namespaces:** `pie-grafana`, `platform-scope`

**Total DNS Names:** 2

### Gateway Changes

**Added to Gateway:**
- ✅ `bkcloudops-chargeback.manulife.ets`
  - Reason: No matching host or wildcard pattern found
- ✅ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: No matching host or wildcard pattern found

### Certificate Changes

**Added to Certificate:**
- ✅ `bkcloudops-chargeback.manulife.ets`
  - Reason: DNS name must be explicitly listed in certificate for TLS validation
- ✅ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: DNS name must be explicitly listed in certificate for TLS validation

---

## Automation Run - 2026-01-17 01:38:55 UTC

**Repository:** `BkCloudOps/cert-automation`

**Namespaces:** `provisioning-services`, `platform-scope`

**Total DNS Names:** 2

### Gateway Changes


**Skipped (Gateway):**
- ⏭️ `testDNS.provisioning-services.pod.cac.plant.aks.sunlife.com`
  - Reason: Covered by existing wildcard pattern '*.provisioning-services.pod.cac.plant.aks.sunlife.com'
- ⏭️ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: Already exists in gateway

### Certificate Changes

**Added to Certificate:**
- ✅ `testDNS.provisioning-services.pod.cac.plant.aks.sunlife.com`
  - Reason: DNS name must be explicitly listed in certificate for TLS validation

**Skipped (Certificate):**
- ⏭️ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: Already exists in certificate

---
