# Security & Health Check Agent

## Overview

`generate_security_health_report` builds a security and health report for the whole Intersight environment from live Intersight data. The implementation is in [securityHealthCheckAgent.ts](src/services/securityHealthCheckAgent.ts), with metrics from [telemetry.ts](src/services/telemetry.ts).

Every figure in the report comes from Intersight. If a source can't be read (for example, the credential's role can't see it), the source is listed in `dataGaps` and that section is reported as unavailable with null scores. A failed source is never reported as zero findings.

## Data Sources

Each collection is read in full: the agent pages through `$top`/`$skip` instead of stopping at the API's default 100 results.

| Report section | Intersight source | What is used |
|---|---|---|
| Device health | `compute/PhysicalSummaries`, `network/ElementSummaries` | `AlarmSummary.Health` (Healthy / Warning / Critical), Intersight's roll-up of each device's active alarms |
| Component state | `processor/Units`, `memory/Units`, `storage/PhysicalDisks`, `equipment/Psus`, `equipment/FanModules` | `OperState` / `DiskState` of installed (`Presence` equipped) components |
| Alarms | `cond/Alarms` with `Severity ne 'Cleared'` | Severity, acknowledgement, suppression, affected object |
| Advisories | `tam/AdvisoryInstances` with `State eq 'active'`, `$expand=Advisory` | Security advisories (PSIRT, with CVEs and CVSS base score), field notices and end-of-life notices that apply to this environment, with the affected devices |
| Firmware | `Firmware` on servers, `Version` on fabric interconnects | Version distribution per model and version drift |
| Licensing | `license/LicenseInfos` | `LicenseState` per license tier in use, `DaysLeft` for trials |
| Secure Boot | `boot/DeviceBootSecurities` | `SecureBoot` as configured in each server's boot policy |
| TPM | `equipment/Tpms` | Installed TPMs, tied to servers through `Ancestors` |
| HCL compliance | `cond/HclStatuses` | Per-server HCL `Status` and `ServerReason` |
| Power, temperature, CPU | `POST telemetry/TimeSeries` (Druid groupBy on `PhysicalEntities`) | Average and peak power (`hw.host`), hottest sensor (`hw.temperature`), CPU C0 utilization (`hw.cpu`) over the last 60 minutes |

## Requirements and Limitations

- **Role:** Read-Only is sufficient for every source, including telemetry.
- **Telemetry license:** metrics need an Intersight Essentials or higher license. Without one, the performance section reports no samples.
- **CPU utilization coverage:** collected for Intersight-managed (IMM) servers and standalone M7 or newer servers. UCS Manager domains report environmental metrics (power, temperature) only.
- **Memory utilization:** Intersight does not report per-server memory utilization, so the report doesn't either.
- **Recommended firmware:** Intersight does not expose a recommended version per device. The firmware section shows version drift; updates driven by security or end-of-life appear under advisories.
- **TPM attribution:** servers are named as lacking a TPM only when every installed TPM can be tied to its server.

## Report Structure

| Field | Contents |
|---|---|
| `status` | `SUCCESS` (all sources read), `PARTIAL` (some sources missing, see `dataGaps`), or `ERROR` (nothing could be read) |
| `dataGaps` | `{source, error}` for each source that failed |
| `summary` | `overallScore`, `securityScore`, `healthScore`, `complianceScore` (0-100, or null when the inputs are unavailable), `scoring` (how the scores are calculated), issue counts, and device/alarm/advisory totals |
| `hardware` | Health counts and the least healthy servers and fabric interconnects; per-type component state counts, with unrecognized states listed in `otherStates` |
| `alarms` | Counts by severity; acknowledged and suppressed counts; unacknowledged critical/warning counts; top alarms; alarms grouped by code and by device type |
| `advisories` | Applicable advisories by type and severity; top advisories with CVEs, base score, link, recommendation and affected devices |
| `firmware` | Versions per server and fabric interconnect model, and the models running more than one version |
| `security` | `licensing`, `secureBoot` and `tpm` subsections |
| `compliance` | HCL `overallStatus` (`COMPLIANT`, `PARTIAL`, `NON_COMPLIANT` or `UNKNOWN`), counts by status, and the servers that are not listed or not verified |
| `performance` | Power (total and top consumers), temperature (hottest servers) and CPU utilization (fleet average and busiest servers) from telemetry |
| `issues` | Findings with category, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), affected resources and remediation |
| `recommendations` | The remediation for each issue, grouped by its severity: `immediate` (critical), `shortTerm` (high), `mediumTerm` (medium), `longTerm` (low) |

## Scoring

- **Health:** the percentage of servers and fabric interconnects that Intersight rates Healthy, with Warning devices counting half.
- **Security:** starts at 100, with these deductions:
  - 15 per critical and 8 per high security advisory that applies, capped at 50 in total
  - 15 if licensing is out of compliance
  - up to 15 in proportion to the share of servers without Secure Boot
  - up to 10 in proportion to the share of servers without a TPM

  It is null when advisories can't be read.
- **Compliance:** the percentage of evaluated servers whose hardware, firmware and OS combination is HCL-validated (or not applicable).
- **Overall:** the mean of the scores that are available.

## Issues Raised

| Finding | Severity |
|---|---|
| Servers or fabric interconnects in Critical health | CRITICAL |
| Unacknowledged critical alarms | CRITICAL |
| Critical security advisories that apply | CRITICAL |
| High-severity security advisories that apply | HIGH |
| Critical or high field notices that apply | HIGH |
| Failed components | HIGH |
| Licensing out of compliance | HIGH |
| Servers not on the HCL | HIGH |
| Devices in Warning health | MEDIUM |
| End-of-life advisories that apply | MEDIUM |
| Secure Boot not enabled | MEDIUM |
| Trial licenses expiring within 30 days | MEDIUM |
| Firmware version drift within a model | LOW |
| Servers without a TPM | LOW |
| Servers whose HCL status couldn't be verified | LOW |

## Related Tool: get_top_resources

`get_top_resources` ranks servers and/or chassis by the same telemetry over a configurable window:

- `metricName`:
  - `CpuUtilization`: servers only, %
  - `PowerConsumption`: average W, with the peak sample
  - `Temperature`: hottest sensor, °C
- `resourceType`: `Server` (default), `Chassis`, or `All`
- `topN` (default 10, max 100) and `windowMinutes` (default 60, min 10)

## Keyword Triggers

The agent fits requests such as:

- **Security:** "security", "vulnerability", "CVE", "compliance", "risk", "audit"
- **Health:** "health", "status", "diagnostic", "problem", "failure", "alarm", "thermal", "power"
- **General:** "report", "summary", "assessment", "advisories", "firmware", "check"

## Troubleshooting

- **`status` is `PARTIAL` or `ERROR`:** read `dataGaps`. A 401/403 means the credential's role can't read that source.
- **The performance section has no samples:**
  - Check that the account has an Essentials or higher license.
  - Check that the servers are a supported platform (see Requirements).
  - Telemetry arrives every 10 minutes on Essentials, so very short windows can be empty.
- **Many servers show HCL status `Incomplete`:** install Cisco UCS Tools on the host OS so Intersight can collect OS and driver inventory.

## Tool Access

**Command:** `generate_security_health_report`  
**Availability:** core and all tool modes  
**Parameters:** none  
**Returns:** the report JSON described above

**Example requests:**
```
"Generate a security health report"
"Check our infrastructure health"
"Which servers are affected by critical security advisories?"
```
