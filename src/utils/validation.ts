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

// Intersight managed object IDs are 24-character hexadecimal strings
const MOID_PATTERN = /^[0-9a-f]{24}$/i;

// Collection paths are a lowercase namespace and a collection name, e.g. "compute/PhysicalSummaries"
const COLLECTION_PATH_PATTERN = /^[a-z]+\/[A-Za-z]+$/;
const POLICY_PATH_PATTERN = /^[a-z]+\/[A-Za-z]*Policies$/;
const POOL_PATHS = [
  'fcpool/Pools',
  'ippool/Pools',
  'iqnpool/Pools',
  'macpool/Pools',
  'resourcepool/Pools',
  'uuidpool/Pools'
];

/**
 * Reject tool arguments named "moid" or "...Moid" that aren't MOIDs. Handlers
 * interpolate these into API paths and filters, so anything else could reach
 * a different object (e.g. "../../server/Profiles/<moid>") or widen a filter.
 */
export function validateMoidArgs(args: Record<string, any>): void {
  for (const [name, value] of Object.entries(args)) {
    if (name !== 'moid' && !name.endsWith('Moid')) {
      continue;
    }
    if (value === undefined || value === null) {
      continue;
    }
    if (typeof value !== 'string' || !MOID_PATTERN.test(value)) {
      throw new Error(`Invalid ${name} ${JSON.stringify(value)}: expected a 24-character hexadecimal Intersight MOID`);
    }
  }
}

export function assertPolicyType(policyType: string): void {
  if (typeof policyType !== 'string' || !POLICY_PATH_PATTERN.test(policyType)) {
    throw new Error(`Invalid policyType ${JSON.stringify(policyType)}: expected a policy collection path such as "bios/Policies"`);
  }
}

export function assertPoolType(poolType: string): void {
  if (!POOL_PATHS.includes(poolType)) {
    throw new Error(`Invalid poolType ${JSON.stringify(poolType)}: expected one of ${POOL_PATHS.join(', ')}`);
  }
}

export function assertResourceType(resourceType: string): void {
  if (typeof resourceType !== 'string' || !COLLECTION_PATH_PATTERN.test(resourceType)) {
    throw new Error(`Invalid resourceType ${JSON.stringify(resourceType)}: expected a collection path such as "compute/PhysicalSummaries"`);
  }
}
