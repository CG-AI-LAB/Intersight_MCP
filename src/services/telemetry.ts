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

/**
 * Server and chassis metrics from Intersight telemetry.
 *
 * Metrics are queried with Druid groupBy queries against the PhysicalEntities
 * datasource (POST /telemetry/TimeSeries). Each metric family is selected by its
 * instrument.name; the stored value field holds a sum, with a matching _count
 * field, so an average is sum / count.
 *
 * Telemetry requires an Intersight Essentials (or higher) license. Intersight
 * does not report per-server memory utilization.
 */

const SERVER_HOST_TYPES = ['compute.Blade', 'compute.RackUnit'];
const CHASSIS_HOST_TYPES = ['equipment.Chassis'];
const DEFAULT_WINDOW_MINUTES = 60;
const REPORT_TOP_N = 5;

export type TopResourceMetric = 'CpuUtilization' | 'MemoryUtilization' | 'PowerConsumption' | 'Temperature';
export type TopResourceType = 'Server' | 'Chassis' | 'All';

interface HostValue {
  name: string;
  moid: string | null;
  hostType: string;
  value: number;
  peak?: number;
}

interface MetricDefinition {
  instrument: string;
  unit: string;
  aggregations: any[];
  // Turns one host's aggregated row into its value; null when the host has no samples
  toValue: (event: any) => { value: number; peak?: number } | null;
}

const average = (sum: unknown, count: unknown) =>
  typeof sum === 'number' && typeof count === 'number' && count > 0 ? sum / count : null;

const METRICS: Record<'power' | 'temperature' | 'cpu', MetricDefinition> = {
  power: {
    instrument: 'hw.host',
    unit: 'W',
    aggregations: [
      { type: 'doubleSum', name: 'sum', fieldName: 'hw.host.power' },
      { type: 'longSum', name: 'count', fieldName: 'hw.host.power_count' },
      { type: 'doubleMax', name: 'max', fieldName: 'hw.host.power_max' },
    ],
    toValue: e => {
      const value = average(e.sum, e.count);
      return value === null ? null : { value, peak: e.max };
    },
  },
  temperature: {
    instrument: 'hw.temperature',
    unit: '°C',
    // The hottest sensor reading on each host during the window
    aggregations: [{ type: 'doubleMax', name: 'max', fieldName: 'hw.temperature_max' }],
    toValue: e => (typeof e.max === 'number' ? { value: e.max } : null),
  },
  cpu: {
    instrument: 'hw.cpu',
    unit: '%',
    // Share of time the CPUs spent in C0 (executing), across all sockets
    aggregations: [
      { type: 'doubleSum', name: 'sum', fieldName: 'hw.cpu.utilization_c0' },
      { type: 'longSum', name: 'count', fieldName: 'hw.cpu.utilization_c0_count' },
    ],
    toValue: e => {
      const value = average(e.sum, e.count);
      return value === null ? null : { value };
    },
  },
};

function hostTypesFor(resourceType: TopResourceType): string[] {
  if (resourceType === 'Chassis') {
    return CHASSIS_HOST_TYPES;
  }
  if (resourceType === 'All') {
    return [...SERVER_HOST_TYPES, ...CHASSIS_HOST_TYPES];
  }
  return SERVER_HOST_TYPES;
}

function resourceTypeOf(hostType: string): string {
  return hostType === 'equipment.Chassis' ? 'Chassis' : 'Server';
}

function clampWindow(windowMinutes?: number): number {
  const minutes = Number(windowMinutes) || DEFAULT_WINDOW_MINUTES;
  // Samples arrive every 10 minutes on Essentials, so shorter windows can be empty
  return Math.min(Math.max(Math.round(minutes), 10), 30 * 24 * 60);
}

async function queryHostMetric(
  api: IntersightApiService,
  metric: MetricDefinition,
  hostTypes: string[],
  windowMinutes: number
): Promise<HostValue[]> {
  const end = new Date();
  const start = new Date(end.getTime() - windowMinutes * 60_000);

  const rows = await api.post('/telemetry/TimeSeries', {
    queryType: 'groupBy',
    dataSource: 'PhysicalEntities',
    granularity: 'all',
    intervals: [`${start.toISOString()}/${end.toISOString()}`],
    dimensions: ['host.name', 'host.id', 'host.type'],
    filter: {
      type: 'and',
      fields: [
        { type: 'selector', dimension: 'instrument.name', value: metric.instrument },
        { type: 'in', dimension: 'host.type', values: hostTypes },
      ],
    },
    aggregations: metric.aggregations,
  });

  if (!Array.isArray(rows)) {
    throw new Error(`Unexpected telemetry response for ${metric.instrument}: expected an array of results`);
  }

  const values: HostValue[] = [];
  for (const row of rows) {
    const event = row?.event || {};
    const result = metric.toValue(event);
    if (!result) {
      continue;
    }
    // host.id is the host's API path, e.g. /api/v1/compute/Blades/<moid>
    const hostId: string = event['host.id'] || '';
    values.push({
      name: event['host.name'] || hostId || 'Unknown',
      moid: hostId ? hostId.split('/').pop() || null : null,
      hostType: event['host.type'] || 'Unknown',
      ...result,
    });
  }
  return values;
}

/**
 * C0 utilization is documented in percent, but Cisco's own dashboards scale it
 * by 100. A fraction can never exceed 1, so values above 1 are already percent.
 */
function normalizeCpuPercent(values: HostValue[]): HostValue[] {
  const isFraction = values.every(v => v.value <= 1);
  return isFraction ? values.map(v => ({ ...v, value: v.value * 100 })) : values;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

function noData(windowMinutes: number) {
  return {
    available: false,
    reason: `No samples in the last ${windowMinutes} minutes. Telemetry needs an Intersight Essentials or higher license and supported hardware.`,
  };
}

function describeFailure(error: unknown) {
  return { available: false, reason: error instanceof Error ? error.message : String(error) };
}

export interface ServerMetrics {
  windowMinutes: number;
  source: string;
  power: any;
  temperature: any;
  cpuUtilization: any;
  memoryUtilization: any;
}

/**
 * Power, temperature and CPU utilization for all servers, for the health report.
 * Throws only if every metric query fails.
 */
export async function getServerMetrics(api: IntersightApiService, windowMinutes?: number): Promise<ServerMetrics> {
  const window = clampWindow(windowMinutes);
  const [power, temperature, cpu] = await Promise.allSettled([
    queryHostMetric(api, METRICS.power, SERVER_HOST_TYPES, window),
    queryHostMetric(api, METRICS.temperature, SERVER_HOST_TYPES, window),
    queryHostMetric(api, METRICS.cpu, SERVER_HOST_TYPES, window),
  ]);

  if (power.status === 'rejected' && temperature.status === 'rejected' && cpu.status === 'rejected') {
    throw power.reason;
  }

  const top = (values: HostValue[]) => [...values].sort((a, b) => b.value - a.value).slice(0, REPORT_TOP_N);

  let powerSummary: any;
  if (power.status === 'rejected') {
    powerSummary = describeFailure(power.reason);
  } else if (power.value.length === 0) {
    powerSummary = noData(window);
  } else {
    powerSummary = {
      available: true,
      serversReporting: power.value.length,
      totalAverageWatts: Math.round(power.value.reduce((sum, v) => sum + v.value, 0)),
      topConsumers: top(power.value).map(v => ({ name: v.name, averageWatts: Math.round(v.value), peakWatts: v.peak })),
    };
  }

  let temperatureSummary: any;
  if (temperature.status === 'rejected') {
    temperatureSummary = describeFailure(temperature.reason);
  } else if (temperature.value.length === 0) {
    temperatureSummary = noData(window);
  } else {
    temperatureSummary = {
      available: true,
      serversReporting: temperature.value.length,
      hottest: top(temperature.value).map(v => ({ name: v.name, maxSensorTemperatureC: v.value })),
    };
  }

  let cpuSummary: any;
  if (cpu.status === 'rejected') {
    cpuSummary = describeFailure(cpu.reason);
  } else if (cpu.value.length === 0) {
    cpuSummary = { ...noData(window), note: 'CPU utilization is collected for Intersight-managed (IMM) servers and standalone M7 or newer servers; UCS Manager domains report environmental metrics only.' };
  } else {
    const values = normalizeCpuPercent(cpu.value);
    cpuSummary = {
      available: true,
      serversReporting: values.length,
      averagePercent: round1(values.reduce((sum, v) => sum + v.value, 0) / values.length),
      busiest: top(values).map(v => ({ name: v.name, averagePercent: round1(v.value) })),
    };
  }

  return {
    windowMinutes: window,
    source: 'Intersight telemetry (PhysicalEntities)',
    power: powerSummary,
    temperature: temperatureSummary,
    cpuUtilization: cpuSummary,
    memoryUtilization: { available: false, reason: 'Intersight telemetry does not report per-server memory utilization' },
  };
}

/**
 * Rank servers and/or chassis by a telemetry metric
 */
export async function getTopResources(
  api: IntersightApiService,
  metricName: TopResourceMetric,
  topN: number = 10,
  resourceType: TopResourceType = 'Server',
  windowMinutes?: number
): Promise<any> {
  if (metricName === 'MemoryUtilization') {
    throw new Error('Intersight telemetry does not report per-server memory utilization. Use list_memory_units for installed memory.');
  }
  if (metricName === 'CpuUtilization' && resourceType === 'Chassis') {
    throw new Error('CPU utilization is reported for servers, not chassis');
  }

  const metric = metricName === 'PowerConsumption' ? METRICS.power
    : metricName === 'Temperature' ? METRICS.temperature
    : metricName === 'CpuUtilization' ? METRICS.cpu
    : null;
  if (!metric) {
    throw new Error(`Unsupported metric '${metricName}' (expected CpuUtilization, PowerConsumption or Temperature)`);
  }

  const window = clampWindow(windowMinutes);
  // CPU utilization is only collected for servers
  const hostTypes = metricName === 'CpuUtilization' ? SERVER_HOST_TYPES : hostTypesFor(resourceType);
  let values = await queryHostMetric(api, metric, hostTypes, window);
  if (metricName === 'CpuUtilization') {
    values = normalizeCpuPercent(values);
  }

  const limit = Math.min(Math.max(Math.round(Number(topN) || 10), 1), 100);
  const results = [...values]
    .sort((a, b) => b.value - a.value)
    .slice(0, limit)
    .map(v => ({
      name: v.name,
      moid: v.moid,
      resourceType: resourceTypeOf(v.hostType),
      metricValue: round1(v.value),
      ...(v.peak !== undefined ? { peakValue: round1(v.peak) } : {}),
      unit: metric.unit,
    }));

  return {
    metricName,
    description: metricName === 'PowerConsumption' ? 'Average power draw over the window (peakValue = highest sample)'
      : metricName === 'Temperature' ? 'Highest sensor temperature on each host over the window'
      : 'Average CPU C0 (busy) residency over the window',
    windowMinutes: window,
    resourceType,
    topN: limit,
    hostsReporting: values.length,
    count: results.length,
    results,
    ...(values.length === 0 ? { note: noData(window).reason } : {}),
  };
}
