/**
 * Dependency resolution and audit query building for dsh-dependency-audit.
 *
 * Split out of index.js so the resolution/attribution logic has no dependency
 * on `@deepseek-ai/dsh-tools` and can be unit-tested directly.
 *
 * ## The defect this module fixes
 *
 * `osvQuery` used to filter out packages with no resolvable version *inside*
 * itself, building a shorter query array than the `deps` list. The caller then
 * mapped OSV results back with `deps[i]` — an index into the *unfiltered* list.
 * As soon as one dependency was missing from `node_modules`, every result
 * shifted by one and vulnerabilities were attributed to the wrong package (and
 * a `null` version was emitted, which the tool's own output schema rejects).
 *
 * The fix is structural: resolution happens once, the query list and the
 * result-mapping list are the *same* array, and a package that cannot be
 * resolved is never queried and can never absorb another package's findings.
 * @module dsh-dependency-audit/core
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

/** OSV batch query endpoint. */
export const OSV_URL = "https://api.osv.dev/v1/querybatch";
/** npm registry base URL. */
export const NPM_REG = "https://registry.npmjs.org";
/** Safety valve on how many dependencies are audited. */
export const MAX_DEPS = 200;

/**
 * Declared output schemas for the two tools.
 *
 * Kept here, free of `@deepseek-ai/dsh-tools`, so the output contract can be
 * asserted in tests without loading the plugin entry point. `index.js` passes
 * these straight through to `defineTool`.
 */

/**
 * Output schema for `audit_vulnerabilities`.
 *
 * `skipped` is declared but deliberately **not** `required: true`: an older
 * consumer validating this payload against a schema that predates the field
 * keeps working, while the implementation always returns it so new consumers can
 * rely on its presence.
 *
 * `additionalProperties` is left permissive at the top level for the same
 * reason. It was `false` before, which would make *any* future field a breaking
 * change — including this one, since a consumer holding the previous schema
 * would reject the extra key. The nested item schemas stay strict, which is
 * where unknown keys would actually signal a mistake.
 */
export const VULNERABILITIES_OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: true,
  properties: {
    totalDeps: { type: "integer", required: true },
    checkedDeps: { type: "integer", required: true },
    vulnerabilityCount: { type: "integer", required: true },
    vulnerabilities: {
      type: "array",
      required: true,
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", required: true },
          version: { type: "string", required: true },
          id: { type: "string", required: true },
          severity: { type: "string", required: true },
          summary: { type: "string", required: true },
          fixed: { type: "string", required: true },
        },
      },
    },
    skipped: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", required: true },
          range: { type: "string", required: true },
          reason: { type: "string", required: true },
        },
      },
    },
  },
};

/** Output schema for `audit_outdated`. */
export const OUTDATED_OUTPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    outdatedCount: { type: "integer", required: true },
    outdated: {
      type: "array",
      required: true,
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string", required: true },
          current: { type: "string", required: true },
          latest: { type: "string", required: true },
          level: { type: "string", required: true },
        },
      },
    },
  },
};

/**
 * Render the vulnerability report as the text the model reads.
 * @param value - the tool's output payload.
 * @returns the model-facing report.
 */
export function renderVulnerabilities(value) {
  const lines = [
    `依赖漏洞审计：${value.checkedDeps}/${value.totalDeps} 个依赖已检查，发现 ${value.vulnerabilityCount} 个漏洞。`,
  ];
  if (value.vulnerabilityCount === 0) {
    lines.push("  （无已知漏洞）");
  } else {
    lines.push(
      ...value.vulnerabilities.slice(0, 30).map(
        (v) =>
          `  - [${v.severity}] ${v.name}@${v.version} → ${v.id}${v.fixed ? `（修复于 ${v.fixed}）` : ""}: ${v.summary}`
      )
    );
    if (value.vulnerabilities.length > 30) {
      lines.push(`  …… 另有 ${value.vulnerabilities.length - 30} 个漏洞未列出`);
    }
  }
  const skipped = value.skipped ?? [];
  if (skipped.length > 0) {
    lines.push(
      `跳过 ${skipped.length} 个未安装依赖（未查询 OSV，不代表安全）：` + skipped.map((s) => s.name).join(", ")
    );
  }
  return lines.join("\n");
}

/**
 * Render the outdated-dependency report.
 * @param value - the tool's output payload.
 * @returns the model-facing report.
 */
export function renderOutdated(value) {
  const rows = value.outdated
    .slice(0, 50)
    .map((o) => `  - ${o.name}: ${o.current} → ${o.latest}（${o.level}）`)
    .join("\n");
  return `过期依赖 ${value.outdatedCount} 个：\n${rows || "  （全部为最新）"}`;
}

/**
 * The fetch implementation used by every network call in this module.
 *
 * Defaults to the platform `fetch` and is only swapped by tests, so an offline
 * run can assert attribution deterministically without patching a global.
 */
let activeFetch = (...args) => fetch(...args);

/**
 * Replace the fetch implementation used for network calls.
 * @param impl - the replacement, or `null` to restore the platform `fetch`.
 */
export function setFetchImpl(impl) {
  activeFetch = impl ? (...args) => impl(...args) : (...args) => fetch(...args);
}

/**
 * Read the installed version of one dependency from `node_modules`.
 * @param root - project root directory.
 * @param name - package name, possibly scoped.
 * @returns the installed version, or `null` when it is not installed.
 */
export async function resolveInstalled(root, name) {
  const isScoped = name.startsWith("@");
  const paths = isScoped
    ? (() => {
        const [scope, rest] = name.split("/");
        return [join(root, "node_modules", scope, rest, "package.json")];
      })()
    : [join(root, "node_modules", name, "package.json")];
  for (const p of paths) {
    try {
      return JSON.parse(await readFile(p, "utf8")).version ?? null;
    } catch {
      // not installed, or unreadable manifest
    }
  }
  return null;
}

/**
 * Resolve every declared dependency exactly once.
 *
 * Returns both the complete declared list and the subset that resolved, so
 * callers never have to re-derive one from the other (which is what caused the
 * index misalignment).
 * @param root - project root directory.
 * @returns `{ declared, resolved, skipped }`.
 * @throws when the project has no readable package.json.
 */
export async function resolvePackages(root) {
  const pkgPath = join(root, "package.json");
  let pkg;
  try {
    pkg = JSON.parse(await readFile(pkgPath, "utf8"));
  } catch {
    throw new Error(`未找到 package.json：${pkgPath}`);
  }

  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

  const declared = [];
  for (const [name, range] of Object.entries(deps)) {
    if (declared.length >= MAX_DEPS) break;
    declared.push({ name, range, version: await resolveInstalled(root, name) });
  }

  const resolved = declared.filter((d) => typeof d.version === "string" && d.version !== "");
  const skipped = declared
    .filter((d) => !(typeof d.version === "string" && d.version !== ""))
    .map((d) => ({ name: d.name, range: d.range, reason: "not installed: no version in node_modules" }));

  return { declared, resolved, skipped };
}

/**
 * Build the OSV batch query payload from resolved packages.
 *
 * The returned array is index-aligned with `resolved`, so a caller may map
 * results back positionally *only* against the same array.
 * @param resolved - the packages returned by {@link resolvePackages}.
 * @returns one query per resolved package, in order.
 */
export function buildOsvQueries(resolved) {
  return resolved.map((p) => ({
    package: { ecosystem: "npm", name: p.name },
    version: p.version,
  }));
}

/**
 * Map OSV batch results back onto the packages that produced them.
 *
 * @param resolved - the exact array passed to {@link buildOsvQueries}.
 * @param results - `results` array from the OSV batch response.
 * @returns one entry per vulnerability, each carrying its owning package.
 */
export function mapOsvResults(resolved, results) {
  const rows = [];
  const seen = new Set();
  const list = Array.isArray(results) ? results : [];

  for (let i = 0; i < list.length; i += 1) {
    // Guard: never read past the list the queries were built from. A response
    // longer than the query list is a protocol error, not an attribution hint.
    const pkg = resolved[i];
    if (!pkg) break;
    for (const vuln of list[i]?.vulns || []) {
      if (!vuln?.id) continue;
      const key = `${pkg.name}@${pkg.version}:${vuln.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({ name: pkg.name, version: pkg.version, id: vuln.id });
    }
  }
  return rows;
}

/**
 * Extract a severity label from an OSV vulnerability record.
 * @param vuln - an OSV vulnerability detail document.
 * @returns an uppercase severity label.
 */
export function severityOf(vuln) {
  const ds = vuln.database_specific?.severity;
  if (typeof ds === "string" && ds) return ds.toUpperCase();
  const sev = Array.isArray(vuln.severity) ? vuln.severity : [];
  let max = 0;
  for (const s of sev) {
    const score = typeof s.score === "string" ? parseFloat(s.score) : s.score;
    if (typeof score === "number" && score > max) max = score;
  }
  if (max >= 9) return "CRITICAL";
  if (max >= 7) return "HIGH";
  if (max >= 4) return "MEDIUM";
  if (max > 0) return "LOW";
  return "UNKNOWN";
}

/**
 * Find the first fixed version recorded in an OSV record.
 * @param vuln - an OSV vulnerability detail document.
 * @returns the fixed version, or `null`.
 */
export function fixedVersion(vuln) {
  for (const a of vuln.affected || []) {
    for (const r of a.ranges || []) {
      for (const e of r.events || []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return null;
}

/**
 * Classify the size of an upgrade.
 * @param cur - current version.
 * @param latest - latest version.
 * @returns `"major"`, `"minor"` or `"patch"`.
 */
export function diffLevel(cur, latest) {
  const [a, b] = [cur, latest].map((v) => v.replace(/^[^0-9]*/, "").split(".").map(Number));
  if (a[0] !== b[0]) return "major";
  if (a[1] !== b[1]) return "minor";
  return "patch";
}

/** Sort vulnerabilities worst-first. */
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, MODERATE: 2, LOW: 3, UNKNOWN: 4 };

/**
 * Order vulnerabilities by severity, then package name for stability.
 * @param rows - vulnerability rows.
 * @returns a new sorted array.
 */
export function sortBySeverity(rows) {
  return [...rows].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 9;
    const sb = SEVERITY_ORDER[b.severity] ?? 9;
    if (sa !== sb) return sa - sb;
    return `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`);
  });
}

/**
 * Assemble the final vulnerability report.
 *
 * Kept separate from network I/O so attribution can be asserted directly.
 * @param resolved - the exact array the queries were built from.
 * @param results - OSV batch `results`.
 * @param details - vulnerability detail documents, index-aligned with the
 *                  deduped id list returned by {@link mapOsvResults}.
 * @returns the tool's output payload.
 */
export function assembleVulnerabilityReport(resolved, results, details) {
  const mapped = mapOsvResults(resolved, results);
  const vulnerabilities = mapped.map((row, i) => {
    const d = details[i];
    return {
      name: row.name,
      version: row.version,
      id: row.id,
      severity: d ? severityOf(d) : "UNKNOWN",
      summary: (d?.summary || "").slice(0, 200),
      fixed: d ? fixedVersion(d) || "" : "",
    };
  });

  return {
    totalDeps: resolved.length,
    checkedDeps: resolved.length,
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilities: sortBySeverity(vulnerabilities),
  };
}

/**
 * Query OSV for a batch of queries.
 * @param queries - payload from {@link buildOsvQueries}.
 * @param fetchImpl - injected fetch for testing.
 * @returns the `results` array.
 */
export async function osvQuery(queries, fetchImpl = null) {
  if (queries.length === 0) return [];
  const res = await (fetchImpl ?? activeFetch)(OSV_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) throw new Error(`OSV 查询失败（HTTP ${res.status}）`);
  const data = await res.json();
  return data.results || [];
}

/**
 * Fetch one vulnerability's detail document.
 * @param id - OSV/GHSA identifier.
 * @param fetchImpl - injected fetch for testing.
 * @returns the document, or `null`.
 */
export async function fetchVulnDetail(id, fetchImpl = null) {
  try {
    const res = await (fetchImpl ?? activeFetch)(`https://api.osv.dev/v1/vulns/${id}`, {
      signal: AbortSignal.timeout(15000),
    });
    if (res.ok) return await res.json();
  } catch {
    // detail is optional; the row still reports UNKNOWN severity
  }
  return null;
}

/**
 * Compare resolved packages against the npm registry.
 * @param resolved - packages with a known version.
 * @param fetchImpl - injected fetch for testing.
 * @returns the outdated packages.
 */
export async function checkOutdated(resolved, fetchImpl = null) {
  const outdated = [];
  for (const p of resolved) {
    if (!p.version) continue;
    let meta = null;
    try {
      const res = await (fetchImpl ?? activeFetch)(`${NPM_REG}/${p.name}/latest`, { signal: AbortSignal.timeout(15000) });
      if (res.ok) meta = await res.json();
    } catch {
      // offline or unpublished: simply not reported
    }
    if (meta?.version && meta.version !== p.version) {
      outdated.push({
        name: p.name,
        current: p.version,
        latest: meta.version,
        level: diffLevel(p.version, meta.version),
      });
    }
  }
  return outdated;
}
