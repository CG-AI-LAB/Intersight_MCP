/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { IntersightApiService } from './intersightApi.js';
import { getServerMetrics, ServerMetrics } from './telemetry.js';

/**
 * Security and Health Check Agent
 *
 * Collects tenant-wide data from Intersight and reduces it to a report covering:
 * - Device health (Intersight's per-device alarm summary) and component state
 * - Active alarms
 * - Advisories (security, field notice, end-of-life) that apply to this tenant
 * - Firmware version consistency across servers and fabric interconnects
 * - Licensing, Secure Boot and TPM posture
 * - HCL compliance per server
 * - Power, temperature and utilization from Intersight telemetry
 *
 * Every figure comes from Intersight. A source that can't be read is listed in
 * dataGaps and reported as unknown (null), never as zero findings.
 */

const SERVER_HEALTH_LIMIT = 20;
const ALARM_LIMIT = 10;
const ADVISORY_LIMIT = 15;
const AFFECTED_DEVICE_LIMIT = 20;
const LICENSE_EXPIRY_WARNING_DAYS = 30;

export interface DataGap {
  source: string;
  error: string;
}

export interface HealthCheckData {
  servers: any[] | null;
  networkElements: any[] | null;
  alarms: any[] | null;
  advisoryInstances: any[] | null;
  licenses: any[] | null;
  tpms: any[] | null;
  bootSecurity: any[] | null;
  serverProfiles: any[] | null;
  bootPolicies: any[] | null;
  hclStatuses: any[] | null;
  components: Record<ComponentType, any[] | null>;
  metrics: ServerMetrics | null;
  sourcesQueried: number;
  gaps: DataGap[];
}

type ComponentType = 'processors' | 'memory' | 'drives' | 'psus' | 'fans';
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface Issue {
  id: string;
  category: 'SECURITY' | 'HARDWARE' | 'FIRMWARE' | 'COMPLIANCE' | 'PERFORMANCE';
  severity: Severity;
  title: string;
  description: string;
  affectedResources: string[];
  remediation: string;
}

export interface SecurityHealthCheckResult {
  status: 'SUCCESS' | 'PARTIAL' | 'ERROR';
  timestamp: string;
  reportType: 'COMPREHENSIVE';
  executionTimeMs: number;
  dataGaps: DataGap[];
  summary: {
    overallScore: number | null;
    securityScore: number | null;
    healthScore: number | null;
    complianceScore: number | null;
    scoring: string;
    criticalIssues: number;
    highIssues: number;
    infrastructureOverview: {
      servers: number | null;
      fabricInterconnects: number | null;
      activeAlarms: number | null;
      applicableAdvisories: number | null;
    };
  };
  hardware: any;
  alarms: any;
  advisories: any;
  firmware: any;
  security: any;
  compliance: any;
  performance: any;
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    mediumTerm: string[];
    longTerm: string[];
  };
  issues: Issue[];
}

const odataFilter = (expression: string) => `$filter=${encodeURIComponent(expression)}`;

/**
 * Collect every data source the report needs. Each source is fetched in full (all pages).
 */
export async function collectHealthCheckData(api: IntersightApiService): Promise<HealthCheckData> {
  const gaps: DataGap[] = [];
  const recordGap = (source: string) => (error: unknown) => {
    gaps.push({ source, error: error instanceof Error ? error.message : String(error) });
    return null;
  };
  const fetchAll = (source: string, endpoint: string): Promise<any[] | null> =>
    api.getAll(endpoint).catch(recordGap(source));

  const sources = [
    fetchAll('servers', '/compute/PhysicalSummaries?$select=Moid,Name,Model,Serial,Firmware,ManagementMode,AlarmSummary'),
    fetchAll('fabricInterconnects', '/network/ElementSummaries?$select=Moid,Name,Model,Serial,Version,AlarmSummary'),
    fetchAll('alarms', `/cond/Alarms?${odataFilter("Severity ne 'Cleared'")}&$select=Code,Severity,Acknowledge,Suppressed,Description,AffectedMoDisplayName,AffectedMoType,CreationTime`),
    // An instance exists only while its advisory applies; State is deprecated and always 'unknown'
    fetchAll('advisories', '/tam/AdvisoryInstances?$expand=Advisory'),
    fetchAll('licenses', '/license/LicenseInfos?$select=LicenseType,LicenseState,DaysLeft'),
    fetchAll('tpm', '/equipment/Tpms?$select=Presence,Ancestors'),
    fetchAll('secureBoot', '/boot/DeviceBootSecurities?$select=SecureBoot,ComputePhysical'),
    fetchAll('serverProfiles', '/server/Profiles?$select=AssociatedServer,PolicyBucket'),
    fetchAll('bootPolicies', '/boot/PrecisionPolicies?$select=Moid,EnforceUefiSecureBoot'),
    fetchAll('hcl', '/cond/HclStatuses?$select=Status,ServerReason,ManagedObject,ServerName,InvModel'),
    fetchAll('processors', '/processor/Units?$select=Presence,OperState'),
    fetchAll('memory', '/memory/Units?$select=Presence,OperState'),
    fetchAll('drives', '/storage/PhysicalDisks?$select=Presence,DiskState'),
    fetchAll('psus', '/equipment/Psus?$select=Presence,OperState'),
    fetchAll('fans', '/equipment/FanModules?$select=Presence,OperState'),
    getServerMetrics(api).catch(recordGap('telemetry')),
  ] as const;

  const [
    servers,
    networkElements,
    alarms,
    advisoryInstances,
    licenses,
    tpms,
    bootSecurity,
    serverProfiles,
    bootPolicies,
    hclStatuses,
    processors,
    memory,
    drives,
    psus,
    fans,
    metrics,
  ] = await Promise.all(sources);

  return {
    servers,
    networkElements,
    alarms,
    advisoryInstances,
    licenses,
    tpms,
    bootSecurity,
    serverProfiles,
    bootPolicies,
    hclStatuses,
    components: { processors, memory, drives, psus, fans },
    metrics,
    sourcesQueried: sources.length,
    gaps,
  };
}

/**
 * Collect data and build the report
 */
export async function generateSecurityHealthReport(api: IntersightApiService): Promise<SecurityHealthCheckResult> {
  const startTime = Date.now();
  const data = await collectHealthCheckData(api);
  const report = createSecurityHealthCheckReport(data);
  report.executionTimeMs = Date.now() - startTime;
  return report;
}

/**
 * Build the report from collected data. Pure function: no API calls.
 */
export function createSecurityHealthCheckReport(data: HealthCheckData): SecurityHealthCheckResult {
  const nameByMoid = buildNameLookup(data.servers, data.networkElements);

  const hardware = analyzeHardware(data.servers, data.networkElements, data.components);
  const alarms = analyzeAlarms(data.alarms);
  const advisories = analyzeAdvisories(data.advisoryInstances, nameByMoid);
  const firmware = analyzeFirmware(data.servers, data.networkElements);
  const security = analyzeSecurity(data);
  const compliance = analyzeCompliance(data.hclStatuses);
  const performance = analyzePerformance(data.metrics);

  const scores = calculateScores(hardware, advisories, security, compliance);
  const issues = generateIssues(hardware, alarms, advisories, firmware, security, compliance);

  const status = data.gaps.length === 0 ? 'SUCCESS' : data.gaps.length >= data.sourcesQueried ? 'ERROR' : 'PARTIAL';

  return {
    status,
    timestamp: new Date().toISOString(),
    reportType: 'COMPREHENSIVE',
    executionTimeMs: 0,
    dataGaps: data.gaps,
    summary: {
      ...scores,
      criticalIssues: issues.filter(i => i.severity === 'CRITICAL').length,
      highIssues: issues.filter(i => i.severity === 'HIGH').length,
      infrastructureOverview: {
        servers: data.servers ? data.servers.length : null,
        fabricInterconnects: data.networkElements ? data.networkElements.length : null,
        activeAlarms: alarms.available ? alarms.total : null,
        applicableAdvisories: advisories.available ? advisories.total : null,
      },
    },
    hardware,
    alarms,
    advisories,
    firmware,
    security,
    compliance,
    performance,
    recommendations: generateRecommendations(issues),
    issues,
  };
}

function unavailable(source: string) {
  return { available: false, reason: `Could not read ${source} from Intersight (see dataGaps)` };
}

function lower(value: unknown): string {
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    counts[k] = (counts[k] || 0) + 1;
  }
  return counts;
}

function buildNameLookup(servers: any[] | null, networkElements: any[] | null): Map<string, string> {
  const names = new Map<string, string>();
  for (const device of [...(servers || []), ...(networkElements || [])]) {
    if (device.Moid) {
      names.set(device.Moid, device.Name || device.Serial || device.Moid);
    }
  }
  return names;
}

// Intersight's own roll-up of a device's active alarms: Healthy, Warning or Critical
function deviceHealth(device: any): 'Healthy' | 'Warning' | 'Critical' | 'Unknown' {
  const health = device.AlarmSummary?.Health;
  return health === 'Healthy' || health === 'Warning' || health === 'Critical' ? health : 'Unknown';
}

function summarizeDeviceHealth(devices: any[]) {
  const byHealth = countBy(devices, deviceHealth);
  const counts = {
    healthy: byHealth.Healthy || 0,
    warning: byHealth.Warning || 0,
    critical: byHealth.Critical || 0,
    unknown: byHealth.Unknown || 0,
  };

  const unhealthy = devices
    .filter(d => deviceHealth(d) === 'Critical' || deviceHealth(d) === 'Warning')
    .sort((a, b) => (b.AlarmSummary?.Critical || 0) - (a.AlarmSummary?.Critical || 0) ||
                    (b.AlarmSummary?.Warning || 0) - (a.AlarmSummary?.Warning || 0))
    .slice(0, SERVER_HEALTH_LIMIT)
    .map(d => ({
      name: d.Name || d.Serial || d.Moid,
      model: d.Model,
      serial: d.Serial,
      health: deviceHealth(d),
      criticalAlarms: d.AlarmSummary?.Critical || 0,
      warningAlarms: d.AlarmSummary?.Warning || 0,
    }));

  return { total: devices.length, ...counts, unhealthy };
}

const HEALTHY_STATES = ['operable', 'ok', 'good', 'enabled', 'powered on'];
const DEGRADED_STATES = ['degraded', 'warning', 'predictive-failure', 'partially-degraded'];
const FAILED_STATES = ['inoperable', 'failed', 'bad', 'disabled'];

function summarizeComponents(components: any[], stateField: string) {
  // Only installed components; absent slots aren't failures
  const installed = components.filter(c => !c.Presence || lower(c.Presence) === 'equipped');
  const summary = { total: installed.length, healthy: 0, degraded: 0, failed: 0, other: 0, otherStates: {} as Record<string, number> };

  for (const component of installed) {
    const state = lower(component[stateField]);
    if (HEALTHY_STATES.includes(state)) {
      summary.healthy++;
    } else if (DEGRADED_STATES.includes(state)) {
      summary.degraded++;
    } else if (FAILED_STATES.includes(state)) {
      summary.failed++;
    } else {
      // Report states we don't recognize instead of silently dropping them
      summary.other++;
      const raw = component[stateField] || '(empty)';
      summary.otherStates[raw] = (summary.otherStates[raw] || 0) + 1;
    }
  }
  return summary;
}

function analyzeHardware(servers: any[] | null, networkElements: any[] | null, components: HealthCheckData['components']) {
  const stateFields: Record<ComponentType, string> = {
    processors: 'OperState',
    memory: 'OperState',
    drives: 'DiskState',
    psus: 'OperState',
    fans: 'OperState',
  };

  const componentDetails: Record<string, any> = {};
  for (const type of Object.keys(stateFields) as ComponentType[]) {
    const list = components[type];
    componentDetails[type] = list ? summarizeComponents(list, stateFields[type]) : unavailable(type);
  }

  return {
    servers: servers ? summarizeDeviceHealth(servers) : unavailable('servers'),
    fabricInterconnects: networkElements ? summarizeDeviceHealth(networkElements) : unavailable('fabric interconnects'),
    componentDetails,
  };
}

function analyzeAlarms(alarms: any[] | null) {
  if (!alarms) {
    return { ...unavailable('alarms'), total: 0 };
  }

  const isAcknowledged = (a: any) => a.Acknowledge === 'Acknowledge';
  // Acknowledged or suppressed alarms are known to an operator; the rest need attention
  const needsAttention = alarms.filter(a => !isAcknowledged(a) && a.Suppressed !== true);
  const bySeverity = countBy(alarms, a => a.Severity || 'Unknown');
  const severityRank: Record<string, number> = { Critical: 0, Warning: 1, Info: 2 };

  const byCode = new Map<string, any[]>();
  for (const alarm of alarms) {
    const code = alarm.Code || 'Unknown';
    byCode.set(code, [...(byCode.get(code) || []), alarm]);
  }

  return {
    available: true,
    total: alarms.length,
    critical: bySeverity.Critical || 0,
    warning: bySeverity.Warning || 0,
    info: bySeverity.Info || 0,
    acknowledged: alarms.filter(isAcknowledged).length,
    suppressed: alarms.filter(a => a.Suppressed === true).length,
    unacknowledgedCritical: needsAttention.filter(a => a.Severity === 'Critical').length,
    unacknowledgedWarning: needsAttention.filter(a => a.Severity === 'Warning').length,
    topAlarms: needsAttention
      .filter(a => a.Severity === 'Critical' || a.Severity === 'Warning')
      .sort((a, b) => (severityRank[a.Severity] ?? 9) - (severityRank[b.Severity] ?? 9) ||
                      String(b.CreationTime || '').localeCompare(String(a.CreationTime || '')))
      .slice(0, ALARM_LIMIT)
      .map(a => ({
        code: a.Code,
        severity: a.Severity,
        description: a.Description,
        affectedDevice: a.AffectedMoDisplayName,
        affectedDeviceType: a.AffectedMoType,
        createTime: a.CreationTime,
      })),
    alarmsByCode: Array.from(byCode.entries())
      .map(([code, list]) => ({
        code,
        count: list.length,
        severity: list[0].Severity,
        description: list[0].Description,
        affectedDevices: Array.from(new Set(list.map(a => a.AffectedMoDisplayName).filter(Boolean))).slice(0, AFFECTED_DEVICE_LIMIT),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, ALARM_LIMIT),
    alarmsByDeviceType: Object.entries(countBy(alarms, a => a.AffectedMoType || 'Unknown'))
      .map(([deviceType, count]) => ({ deviceType, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, ALARM_LIMIT),
  };
}

const ADVISORY_SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, na: 5 };

function advisoryType(advisory: any): string {
  // Security advisories are their own class (tam.SecurityAdvisory) and have no Type field
  if (advisory?.ObjectType === 'tam.SecurityAdvisory') {
    return 'securityAdvisory';
  }
  return advisory?.Type || 'unknown';
}

function analyzeAdvisories(instances: any[] | null, nameByMoid: Map<string, string>) {
  if (!instances) {
    return { ...unavailable('advisories'), total: 0 };
  }

  // One entry per advisory, with the tenant objects it currently applies to
  const byAdvisory = new Map<string, { advisory: any; affected: Set<string> }>();
  for (const instance of instances) {
    const advisory = instance.Advisory || {};
    const key = advisory.Moid || 'unknown';
    if (!byAdvisory.has(key)) {
      byAdvisory.set(key, { advisory, affected: new Set() });
    }
    const moid = instance.AffectedObjectMoid;
    byAdvisory.get(key)!.affected.add(nameByMoid.get(moid) || `${instance.AffectedObjectType || 'object'} ${moid}`);
  }

  const entries = Array.from(byAdvisory.values()).map(({ advisory, affected }) => ({
    id: advisory.AdvisoryId || advisory.Moid,
    title: advisory.Name,
    type: advisoryType(advisory),
    severity: lower(advisory.Severity?.Level) || 'unknown',
    cveIds: Array.isArray(advisory.CveIds) && advisory.CveIds.length > 0 ? advisory.CveIds : undefined,
    baseScore: advisory.BaseScore || undefined,
    url: advisory.ExternalUrl,
    datePublished: advisory.DatePublished,
    recommendation: advisory.Recommendation ? String(advisory.Recommendation).substring(0, 500) : undefined,
    affectedCount: affected.size,
    affectedDevices: Array.from(affected).slice(0, AFFECTED_DEVICE_LIMIT),
  }));

  const ofType = (type: string) => entries.filter(e => e.type === type);
  const countSeverity = (list: typeof entries, severity: string) => list.filter(e => e.severity === severity).length;
  const security = ofType('securityAdvisory');

  return {
    available: true,
    total: entries.length,
    affectedObjects: new Set(instances.map(i => i.AffectedObjectMoid)).size,
    bySeverity: countBy(entries, e => e.severity),
    securityAdvisories: { total: security.length, critical: countSeverity(security, 'critical'), high: countSeverity(security, 'high') },
    fieldNotices: { total: ofType('fieldNotice').length, critical: countSeverity(ofType('fieldNotice'), 'critical'), high: countSeverity(ofType('fieldNotice'), 'high') },
    eolAdvisories: { total: ofType('eolAdvisory').length },
    topAdvisories: entries
      .sort((a, b) => (ADVISORY_SEVERITY_RANK[a.severity] ?? 9) - (ADVISORY_SEVERITY_RANK[b.severity] ?? 9) || b.affectedCount - a.affectedCount)
      .slice(0, ADVISORY_LIMIT),
  };
}

function versionDistribution(devices: any[], versionField: string) {
  const byModel = new Map<string, Record<string, number>>();
  for (const device of devices) {
    const model = device.Model || 'Unknown';
    const version = device[versionField] || 'Unknown';
    const versions = byModel.get(model) || {};
    versions[version] = (versions[version] || 0) + 1;
    byModel.set(model, versions);
  }

  return Array.from(byModel.entries())
    .map(([model, versions]) => ({
      model,
      deviceCount: Object.values(versions).reduce((sum, n) => sum + n, 0),
      versions: Object.entries(versions)
        .map(([version, count]) => ({ version, count }))
        .sort((a, b) => b.count - a.count),
    }))
    .sort((a, b) => b.deviceCount - a.deviceCount);
}

function analyzeFirmware(servers: any[] | null, networkElements: any[] | null) {
  if (!servers && !networkElements) {
    return unavailable('servers or fabric interconnects');
  }

  const serverVersions = servers ? versionDistribution(servers, 'Firmware') : null;
  const fiVersions = networkElements ? versionDistribution(networkElements, 'Version') : null;
  const withDrift = (groups: ReturnType<typeof versionDistribution> | null) =>
    (groups || []).filter(g => g.versions.length > 1);

  return {
    available: true,
    note: 'Intersight does not report a recommended version per device. Version drift is shown here; firmware updates required for security or end-of-life are listed under advisories.',
    servers: serverVersions,
    fabricInterconnects: fiVersions,
    modelsWithVersionDrift: [...withDrift(serverVersions), ...withDrift(fiVersions)].map(g => ({
      model: g.model,
      versions: g.versions.map(v => `${v.version} (${v.count})`),
    })),
  };
}

const NON_COMPLIANT_LICENSE_STATES = ['OutOfCompliance', 'GraceExpired', 'TrialExpired'];

function analyzeLicenses(licenses: any[]) {
  // NotLicensed entries are license tiers this account doesn't use
  const inUse = licenses.filter(l => l.LicenseState && l.LicenseState !== 'NotLicensed');
  const nonCompliant = inUse.filter(l => NON_COMPLIANT_LICENSE_STATES.includes(l.LicenseState));
  const expiringTrials = inUse.filter(l =>
    l.LicenseState === 'TrialPeriod' && typeof l.DaysLeft === 'number' && l.DaysLeft <= LICENSE_EXPIRY_WARNING_DAYS);

  return {
    available: true,
    compliance: nonCompliant.length > 0 ? 'NON_COMPLIANT' : 'COMPLIANT',
    licenses: inUse.map(l => ({ type: l.LicenseType, state: l.LicenseState, daysLeft: l.DaysLeft })),
    nonCompliant: nonCompliant.map(l => `${l.LicenseType}: ${l.LicenseState}`),
    expiringTrials: expiringTrials.map(l => `${l.LicenseType}: ${l.DaysLeft} days left`),
  };
}

function analyzeSecureBoot(
  bootSecurity: any[] | null,
  serverProfiles: any[] | null,
  bootPolicies: any[] | null,
  servers: any[] | null
) {
  // Both sources reflect the setting configured in each server's boot policy
  const enabled = new Set<string>();
  const disabled = new Set<string>();
  for (const record of bootSecurity || []) {
    const moid = record.ComputePhysical?.Moid;
    if (!moid) {
      continue;
    }
    (lower(record.SecureBoot) === 'enabled' ? enabled : disabled).add(moid);
  }

  // Intersight-managed servers have no DeviceBootSecurity record; use the boot
  // policy of the server profile deployed to them instead
  const enforceByPolicy = new Map<string, boolean>(
    (bootPolicies || []).map(p => [p.Moid, p.EnforceUefiSecureBoot === true]));
  for (const profile of serverProfiles || []) {
    const moid = profile.AssociatedServer?.Moid;
    const policyRef = (profile.PolicyBucket || []).find((p: any) => p.ObjectType === 'boot.PrecisionPolicy');
    if (!moid || enabled.has(moid) || disabled.has(moid) || !policyRef || !enforceByPolicy.has(policyRef.Moid)) {
      continue;
    }
    (enforceByPolicy.get(policyRef.Moid) ? enabled : disabled).add(moid);
  }

  const nameOf = (moid: string) => servers?.find(s => s.Moid === moid)?.Name || moid;
  const reported = new Set([...enabled, ...disabled]);

  return {
    available: true,
    serversEnabled: enabled.size,
    serversDisabled: disabled.size,
    serversNotReported: servers ? servers.filter(s => !reported.has(s.Moid)).length : null,
    disabledServers: Array.from(disabled).slice(0, AFFECTED_DEVICE_LIMIT).map(nameOf),
  };
}

function analyzeTpm(tpms: any[], servers: any[] | null) {
  const present = tpms.filter(t => !t.Presence || lower(t.Presence) === 'equipped');
  const serversWithTpm = new Set<string>();
  for (const tpm of present) {
    const server = (tpm.Ancestors || []).find((a: any) =>
      a.ObjectType === 'compute.Blade' || a.ObjectType === 'compute.RackUnit');
    if (server?.Moid) {
      serversWithTpm.add(server.Moid);
    }
  }

  // Only name servers without a TPM if every installed TPM could be tied to its server
  const attributable = servers !== null && serversWithTpm.size === present.length;
  const withoutTpm = attributable ? servers!.filter(s => !serversWithTpm.has(s.Moid)) : null;

  return {
    available: true,
    tpmsInstalled: present.length,
    serversWithTpm: attributable ? serversWithTpm.size : null,
    serversWithoutTpm: withoutTpm ? withoutTpm.length : null,
    serversWithoutTpmNames: withoutTpm ? withoutTpm.slice(0, AFFECTED_DEVICE_LIMIT).map(s => s.Name || s.Moid) : undefined,
  };
}

function analyzeSecurity(data: HealthCheckData) {
  const { licenses, tpms, bootSecurity, serverProfiles, bootPolicies, servers } = data;
  const secureBootReadable = bootSecurity !== null || (serverProfiles !== null && bootPolicies !== null);

  return {
    licensing: licenses ? analyzeLicenses(licenses) : unavailable('licenses'),
    secureBoot: secureBootReadable
      ? analyzeSecureBoot(bootSecurity, serverProfiles, bootPolicies, servers)
      : unavailable('Secure Boot settings'),
    tpm: tpms ? analyzeTpm(tpms, servers) : unavailable('TPM inventory'),
  };
}

const HCL_COMPLIANT = ['Validated', 'Not-Applicable'];
const HCL_NON_COMPLIANT = ['Not-Listed'];

function analyzeCompliance(hclStatuses: any[] | null) {
  if (!hclStatuses) {
    return unavailable('HCL status');
  }

  const byStatus = countBy(hclStatuses, h => h.Status || 'Unknown');
  const nonCompliant = hclStatuses.filter(h => HCL_NON_COMPLIANT.includes(h.Status));
  // Incomplete usually means OS/driver inventory is missing (e.g. UCS Tools not installed)
  const unverified = hclStatuses.filter(h => !HCL_COMPLIANT.includes(h.Status) && !HCL_NON_COMPLIANT.includes(h.Status));

  let overallStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL' | 'UNKNOWN';
  if (hclStatuses.length === 0) {
    overallStatus = 'UNKNOWN';
  } else if (nonCompliant.length > 0) {
    overallStatus = 'NON_COMPLIANT';
  } else if (unverified.length > 0) {
    overallStatus = 'PARTIAL';
  } else {
    overallStatus = 'COMPLIANT';
  }

  const describe = (h: any) => ({
    server: h.ServerName || h.ManagedObject?.Moid,
    model: h.InvModel,
    status: h.Status,
    reason: h.ServerReason,
  });

  return {
    available: true,
    overallStatus,
    serversEvaluated: hclStatuses.length,
    serversNotListed: nonCompliant.length,
    serversUnverified: unverified.length,
    byStatus,
    nonCompliantServers: nonCompliant.slice(0, AFFECTED_DEVICE_LIMIT).map(describe),
    unverifiedServers: unverified.slice(0, AFFECTED_DEVICE_LIMIT).map(describe),
  };
}

function analyzePerformance(metrics: ServerMetrics | null) {
  if (!metrics) {
    return unavailable('telemetry');
  }
  return { available: true, ...metrics };
}

const round = (n: number) => Math.round(n);

function calculateScores(hardware: any, advisories: any, security: any, compliance: any) {
  // Health: share of servers and fabric interconnects Intersight rates healthy; warnings count half
  let healthScore: number | null = null;
  const devices = [hardware.servers, hardware.fabricInterconnects].filter(d => d.available !== false);
  const rated = devices.reduce((sum, d) => sum + d.healthy + d.warning + d.critical, 0);
  if (rated > 0) {
    const points = devices.reduce((sum, d) => sum + d.healthy + d.warning * 0.5, 0);
    healthScore = round((points / rated) * 100);
  }

  // Security: deductions for applicable advisories and posture gaps, each capped
  let securityScore: number | null = null;
  if (advisories.available) {
    let score = 100;
    score -= Math.min(50, advisories.securityAdvisories.critical * 15 + advisories.securityAdvisories.high * 8);
    if (security.licensing.available && security.licensing.compliance !== 'COMPLIANT') {
      score -= 15;
    }
    const sb = security.secureBoot;
    if (sb.available && sb.serversEnabled + sb.serversDisabled > 0) {
      score -= round(15 * sb.serversDisabled / (sb.serversEnabled + sb.serversDisabled));
    }
    const tpm = security.tpm;
    if (tpm.available && tpm.serversWithTpm !== null && tpm.serversWithTpm + tpm.serversWithoutTpm > 0) {
      score -= round(10 * tpm.serversWithoutTpm / (tpm.serversWithTpm + tpm.serversWithoutTpm));
    }
    securityScore = Math.max(0, score);
  }

  // Compliance: of the servers with a definite HCL result, the share that are validated.
  // Unverified servers (e.g. Incomplete: OS driver inventory missing) are reported, not scored.
  let complianceScore: number | null = null;
  if (compliance.available) {
    const ok = HCL_COMPLIANT.reduce((sum, s) => sum + (compliance.byStatus[s] || 0), 0);
    const determinate = ok + compliance.serversNotListed;
    complianceScore = determinate > 0 ? round((ok / determinate) * 100) : null;
  }

  const known = [securityScore, healthScore, complianceScore].filter((s): s is number => s !== null);

  return {
    overallScore: known.length > 0 ? round(known.reduce((a, b) => a + b, 0) / known.length) : null,
    securityScore,
    healthScore,
    complianceScore,
    scoring: 'health = % of servers/FIs rated Healthy by Intersight (Warning counts half); ' +
      'security = 100 minus capped deductions for critical/high security advisories, license non-compliance, ' +
      'and the share of servers without Secure Boot or TPM; compliance = % HCL-validated among servers with a ' +
      'definite HCL result (unverified servers are listed but not scored). ' +
      'overall = mean of the available scores. A null score means its data could not be read or there was nothing to score.',
  };
}

function generateIssues(hardware: any, alarms: any, advisories: any, firmware: any, security: any, compliance: any): Issue[] {
  const issues: Issue[] = [];
  let id = 1;
  const add = (issue: Omit<Issue, 'id'>, prefix: string) => issues.push({ id: `${prefix}-${id++}`, ...issue });

  for (const [label, devices] of [['servers', hardware.servers], ['fabric interconnects', hardware.fabricInterconnects]] as const) {
    if (devices.available === false) {
      continue;
    }
    if (devices.critical > 0) {
      add({
        category: 'HARDWARE',
        severity: 'CRITICAL',
        title: `${devices.critical} ${label} in Critical health`,
        description: `Intersight rates ${devices.critical} of ${devices.total} ${label} Critical based on their active alarms`,
        affectedResources: devices.unhealthy.filter((d: any) => d.health === 'Critical').map((d: any) => d.name),
        remediation: `Investigate the critical alarms on these ${label}`,
      }, 'HW');
    }
    if (devices.warning > 0) {
      add({
        category: 'HARDWARE',
        severity: 'MEDIUM',
        title: `${devices.warning} ${label} in Warning health`,
        description: `Intersight rates ${devices.warning} of ${devices.total} ${label} Warning based on their active alarms`,
        affectedResources: devices.unhealthy.filter((d: any) => d.health === 'Warning').map((d: any) => d.name),
        remediation: `Review the warning alarms on these ${label}`,
      }, 'HW');
    }
  }

  const failedComponents = Object.entries(hardware.componentDetails)
    .filter(([, c]: [string, any]) => c.available !== false && c.failed > 0)
    .map(([type, c]: [string, any]) => `${c.failed} ${type}`);
  if (failedComponents.length > 0) {
    add({
      category: 'HARDWARE',
      severity: 'HIGH',
      title: `Failed components: ${failedComponents.join(', ')}`,
      description: 'Installed components report an inoperable or failed state',
      affectedResources: [],
      remediation: 'Open a TAC case or replace the failed components',
    }, 'HW');
  }

  const degradedComponents = Object.entries(hardware.componentDetails)
    .filter(([, c]: [string, any]) => c.available !== false && c.degraded > 0)
    .map(([type, c]: [string, any]) => `${c.degraded} ${type}`);
  if (degradedComponents.length > 0) {
    add({
      category: 'HARDWARE',
      severity: 'MEDIUM',
      title: `Degraded components: ${degradedComponents.join(', ')}`,
      description: 'Installed components report a degraded or warning state',
      affectedResources: [],
      remediation: 'Check the related alarms and plan replacement of the degraded components',
    }, 'HW');
  }

  if (alarms.available && alarms.unacknowledgedCritical > 0) {
    add({
      category: 'HARDWARE',
      severity: 'CRITICAL',
      title: `${alarms.unacknowledgedCritical} unacknowledged critical alarms`,
      description: `${alarms.unacknowledgedCritical} critical alarms are active and not acknowledged or suppressed`,
      affectedResources: alarms.topAlarms.filter((a: any) => a.severity === 'Critical').map((a: any) => a.affectedDevice),
      remediation: 'Resolve each critical alarm, or acknowledge it once it is being handled',
    }, 'ALM');
  }

  if (advisories.available) {
    const top = advisories.topAdvisories;
    const critical = top.filter((a: any) => a.type === 'securityAdvisory' && a.severity === 'critical');
    const high = top.filter((a: any) => a.type === 'securityAdvisory' && a.severity === 'high');
    if (advisories.securityAdvisories.critical > 0) {
      add({
        category: 'SECURITY',
        severity: 'CRITICAL',
        title: `${advisories.securityAdvisories.critical} critical security advisories apply to this environment`,
        description: critical.map((a: any) => `${a.title}${a.cveIds ? ` (${a.cveIds.join(', ')})` : ''}: ${a.affectedCount} affected`).join('; '),
        affectedResources: Array.from(new Set(critical.flatMap((a: any) => a.affectedDevices))) as string[],
        remediation: 'Apply the fixed firmware or workaround from each advisory',
      }, 'SEC');
    }
    if (advisories.securityAdvisories.high > 0) {
      add({
        category: 'SECURITY',
        severity: 'HIGH',
        title: `${advisories.securityAdvisories.high} high-severity security advisories apply to this environment`,
        description: high.map((a: any) => `${a.title}${a.cveIds ? ` (${a.cveIds.join(', ')})` : ''}: ${a.affectedCount} affected`).join('; '),
        affectedResources: Array.from(new Set(high.flatMap((a: any) => a.affectedDevices))) as string[],
        remediation: 'Schedule the fixed firmware or workaround from each advisory',
      }, 'SEC');
    }
    const urgentNotices = advisories.fieldNotices.critical + advisories.fieldNotices.high;
    if (urgentNotices > 0) {
      add({
        category: 'HARDWARE',
        severity: 'HIGH',
        title: `${urgentNotices} critical/high field notices apply to this environment`,
        description: 'Cisco field notices for hardware or software in this environment',
        affectedResources: [],
        remediation: 'Follow the remediation in each field notice',
      }, 'FN');
    }
    if (advisories.eolAdvisories.total > 0) {
      add({
        category: 'FIRMWARE',
        severity: 'MEDIUM',
        title: `${advisories.eolAdvisories.total} end-of-life advisories apply to this environment`,
        description: 'Hardware or software in this environment has reached or announced end-of-life milestones',
        affectedResources: [],
        remediation: 'Plan replacement or upgrade before end of support',
      }, 'EOL');
    }
  }

  if (firmware.available && firmware.modelsWithVersionDrift.length > 0) {
    add({
      category: 'FIRMWARE',
      severity: 'LOW',
      title: `${firmware.modelsWithVersionDrift.length} models run more than one firmware version`,
      description: firmware.modelsWithVersionDrift.map((m: any) => `${m.model}: ${m.versions.join(', ')}`).join('; '),
      affectedResources: firmware.modelsWithVersionDrift.map((m: any) => m.model),
      remediation: 'Standardize each model on one firmware version',
    }, 'FW');
  }

  const licensing = security.licensing;
  if (licensing.available && licensing.nonCompliant.length > 0) {
    add({
      category: 'COMPLIANCE',
      severity: 'HIGH',
      title: 'Intersight licensing is out of compliance',
      description: licensing.nonCompliant.join('; '),
      affectedResources: [],
      remediation: 'Renew or true up the affected Intersight licenses',
    }, 'LIC');
  }
  if (licensing.available && licensing.expiringTrials.length > 0) {
    add({
      category: 'COMPLIANCE',
      severity: 'MEDIUM',
      title: 'Intersight trial licenses expire soon',
      description: licensing.expiringTrials.join('; '),
      affectedResources: [],
      remediation: 'Purchase licenses before the trial ends',
    }, 'LIC');
  }

  const secureBoot = security.secureBoot;
  if (secureBoot.available && secureBoot.serversDisabled > 0) {
    add({
      category: 'SECURITY',
      severity: 'MEDIUM',
      title: `Secure Boot is not enabled on ${secureBoot.serversDisabled} servers`,
      description: 'The boot policy for these servers does not enable UEFI Secure Boot',
      affectedResources: secureBoot.disabledServers,
      remediation: 'Enable UEFI Secure Boot in the boot policy and redeploy the server profile',
    }, 'SBOOT');
  }

  const tpm = security.tpm;
  if (tpm.available && tpm.serversWithoutTpm > 0) {
    add({
      category: 'SECURITY',
      severity: 'LOW',
      title: `${tpm.serversWithoutTpm} servers have no TPM installed`,
      description: 'No Trusted Platform Module is inventoried on these servers',
      affectedResources: tpm.serversWithoutTpmNames,
      remediation: 'Install a TPM where measured boot or disk encryption is required',
    }, 'TPM');
  }

  if (compliance.available && compliance.serversNotListed > 0) {
    add({
      category: 'COMPLIANCE',
      severity: 'HIGH',
      title: `${compliance.serversNotListed} servers are not on the Cisco HCL`,
      description: 'The hardware, firmware and OS combination on these servers is not a validated HCL combination',
      affectedResources: compliance.nonCompliantServers.map((s: any) => `${s.server} (${s.reason})`),
      remediation: 'Change the firmware, OS or drivers to an HCL-validated combination',
    }, 'HCL');
  }
  if (compliance.available && compliance.serversUnverified > 0) {
    add({
      category: 'COMPLIANCE',
      severity: 'LOW',
      title: `${compliance.serversUnverified} servers could not be HCL-validated`,
      description: 'HCL status is incomplete or not evaluated, usually because OS and driver inventory is missing',
      affectedResources: compliance.unverifiedServers.map((s: any) => `${s.server} (${s.status})`),
      remediation: 'Install Cisco UCS Tools on the host OS so Intersight can collect OS and driver inventory',
    }, 'HCL');
  }

  return issues;
}

function generateRecommendations(issues: Issue[]) {
  // Every recommendation comes from a finding; urgency follows the finding's severity
  const forSeverity = (severity: Severity) =>
    issues.filter(i => i.severity === severity).map(i => `${i.remediation} (${i.title})`);

  return {
    immediate: forSeverity('CRITICAL'),
    shortTerm: forSeverity('HIGH'),
    mediumTerm: forSeverity('MEDIUM'),
    longTerm: forSeverity('LOW'),
  };
}
