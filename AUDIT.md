# Certificate Automation Audit Log

This file tracks all automated changes to gateway and certificate configurations.

---

## Automation Run - 2026-01-16 18:35:27 UTC

**Repository:** `BkCloudOps/cert-automation`

**Namespaces:** `pie-grafana`, `platform-scope`

**Total DNS Names:** 2

### Gateway Changes


**Skipped (Gateway):**
- ⏭️ `bkcloudops-chargeback.manulife.ets`
  - Reason: Could not find namespace section for 'pie-grafana'
- ⏭️ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: Could not find namespace section for 'platform-scope'

### Certificate Changes

**Added to Certificate:**
- ✅ `bkcloudops-chargeback.manulife.ets`
  - Reason: DNS name must be explicitly listed in certificate for TLS validation
- ✅ `example03.platform-scope.pod.cac.corp.aks.sunlife.com`
  - Reason: DNS name must be explicitly listed in certificate for TLS validation

---
