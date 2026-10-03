/**
 * Regression tests for package/vulnerability attribution.
 *
 * The defect: `osvQuery()` filtered out version-less dependencies internally, so
 * the OSV `results` array was shorter than the `deps` array it was later indexed
 * against. A single uninstalled dependency shifted every subsequent result and
 * attributed vulnerabilities to the wrong package (and emitted a `null` version,
 * which the tool's own output schema rejects).
 *
 * Central invariant asserted after every scenario: for every reported
 * vulnerability, `name@version` must exactly match a query that was actually
 * sent to OSV, and no finding may carry an empty or null version.
 *
 * Run: node --test test/
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  assembleVulnerabilityReport,
  buildOsvQueries,
  checkOutdated,
  diffLevel,
  mapOsvResults,
  OUTDATED_OUTPUT_SCHEMA,
  renderOutdated,
  renderVulnerabilities,
  resolveInstalled,
  resolvePackages,
  severityOf,
  VULNERABILITIES_OUTPUT_SCHEMA,
} from "../lib/core.js";

// ─── fixture helpers ────────────────────────────────────────────────────────

/**
 * Create a project with the given dependencies; only `installed` are placed in
 * node_modules, so the others resolve to null exactly as a partial install does.
 */
function makeProject(deps, installed) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-audit-"));
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: deps }, null, 2)
  );
  for (const [name, version] of Object.entries(installed)) {
    const dir = path.join(root, "node_modules", name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, version }));
  }
  return root;
}

const cleanup = (root) => fs.rmSync(root, { recursive: true, force: true });

/**
 * Build an OSV response with one result per query, vulns keyed by the package
 * name the query actually carried. This proves attribution from the response
 * side: a mis-indexed result surfaces under the wrong name.
 */
function fakeOsvResponse(queries, vulnsByPackage) {
  return {
    results: queries.map((q) => {
      const ids = vulnsByPackage[q.package.name] || [];
      return ids.length ? { vulns: ids.map((id) => ({ id })) } : {};
    }),
  };
}

/** Run the pipeline offline, returning the report and the exact queries sent. */
async function runAudit(root, vulnsByPackage = {}) {
  const { declared, resolved, skipped } = await resolvePackages(root);
  const queries = buildOsvQueries(resolved);
  const response = fakeOsvResponse(queries, vulnsByPackage);
  const details = queries.map(() => null);
  const report = {
    ...assembleVulnerabilityReport(resolved, response.results, details),
    totalDeps: declared.length,
    checkedDeps: resolved.length,
    skipped,
  };
  return { declared, resolved, skipped, queries, report };
}

const queriedSet = (queries) => new Set(queries.map((q) => `${q.package.name}@${q.version}`));

/** Every reported vulnerability must map onto a query that was really sent. */
function assertAttribution(report, queries) {
  const sent = queriedSet(queries);
  const sentNames = new Set(queries.map((q) => q.package.name));
  for (const v of report.vulnerabilities) {
    assert.ok(
      typeof v.version === "string" && v.version.length > 0,
      `vulnerability ${v.id} must carry a non-empty version, got ${JSON.stringify(v.version)}`
    );
    assert.ok(
      sent.has(`${v.name}@${v.version}`),
      `reported ${v.name}@${v.version} (${v.id}) but that pair was never queried; sent: ${[...sent].join(", ") || "(none)"}`
    );
    assert.ok(sentNames.has(v.name), `${v.name} was reported but never queried`);
  }
}

const NAMES = ["alpha", "bravo", "charlie", "delta"];
const DEPS = { alpha: "^1.0.0", bravo: "^2.0.0", charlie: "^3.0.0", delta: "^4.0.0" };
const VULN_BRAVO = "GHSA-bbbb-2222-2222";

// ─── healthy path ───────────────────────────────────────────────────────────

test("all deps installed: one query per dep, correct attribution", async () => {
  const root = makeProject(DEPS, { alpha: "1.0.0", bravo: "2.0.0", charlie: "3.0.0", delta: "4.0.0" });
  try {
    const { declared, resolved, skipped, queries, report } = await runAudit(root, {
      alpha: ["GHSA-a1"],
      charlie: ["GHSA-c1"],
    });

    assert.equal(declared.length, 4);
    assert.equal(resolved.length, 4);
    assert.equal(skipped.length, 0);
    assert.equal(queries.length, 4);
    assert.deepEqual(queries[0], { package: { ecosystem: "npm", name: "alpha" }, version: "1.0.0" });
    assert.equal(report.totalDeps, 4);
    assert.equal(report.checkedDeps, 4);
    assert.equal(report.vulnerabilityCount, 2);
    assertAttribution(report, queries);

    const byName = Object.fromEntries(report.vulnerabilities.map((v) => [v.name, v.version]));
    assert.equal(byName.alpha, "1.0.0");
    assert.equal(byName.charlie, "3.0.0");
  } finally {
    cleanup(root);
  }
});

// ─── missing versions in every position ─────────────────────────────────────

for (const [label, installed] of [
  ["first dep missing", { bravo: "2.0.0", charlie: "3.0.0", delta: "4.0.0" }],
  ["middle dep missing", { alpha: "1.0.0", charlie: "3.0.0", delta: "4.0.0" }],
  ["last dep missing", { alpha: "1.0.0", bravo: "2.0.0", charlie: "3.0.0" }],
  ["two deps missing", { bravo: "2.0.0", delta: "4.0.0" }],
  ["three deps missing", { delta: "4.0.0" }],
]) {
  test(`${label}: no misattribution, unresolved deps skipped`, async () => {
    const root = makeProject(DEPS, installed);
    try {
      const missing = NAMES.filter((n) => !(n in installed));
      const { declared, resolved, skipped, queries, report } = await runAudit(root, {
        alpha: ["GHSA-a1"],
        bravo: [VULN_BRAVO],
        charlie: ["GHSA-c1"],
      });

      assert.equal(declared.length, 4, "every declared dep is counted");
      assert.equal(resolved.length, Object.keys(installed).length);
      assert.equal(skipped.length, missing.length);
      assert.deepEqual(skipped.map((s) => s.name).sort(), [...missing].sort());

      // Exactly one query per resolved dep, never one per declared dep.
      assert.equal(queries.length, resolved.length);
      for (const q of queries) {
        assert.equal(installed[q.package.name], q.version, `query for ${q.package.name} carries the wrong version`);
      }

      assertAttribution(report, queries);

      const reported = report.vulnerabilities.map((v) => v.name);
      for (const m of missing) {
        assert.ok(!reported.includes(m), `${m} is not installed and must not receive a vulnerability`);
      }
      for (const v of report.vulnerabilities) {
        assert.notEqual(v.version, null);
        assert.notEqual(v.version, undefined);
      }
    } finally {
      cleanup(root);
    }
  });
}

test("all deps missing: zero queries, zero vulnerabilities, all skipped", async () => {
  const root = makeProject(DEPS, {});
  try {
    const { declared, resolved, skipped, queries, report } = await runAudit(root, { alpha: ["GHSA-a1"] });

    assert.equal(declared.length, 4);
    assert.equal(resolved.length, 0);
    assert.equal(skipped.length, 4);
    assert.equal(queries.length, 0, "an unresolved dep must never be sent to OSV");
    assert.equal(report.vulnerabilityCount, 0);
    assert.equal(report.vulnerabilities.length, 0);
    assertAttribution(report, queries);
    assert.equal(report.totalDeps, 4);
    assert.equal(report.checkedDeps, 0, "nothing installed means nothing was checked");
  } finally {
    cleanup(root);
  }
});

// ─── OSV response shapes ────────────────────────────────────────────────────

test("OSV with no results yields an empty, well-formed report", async () => {
  const root = makeProject(DEPS, { alpha: "1.0.0", bravo: "2.0.0", charlie: "3.0.0", delta: "4.0.0" });
  try {
    const { queries, report } = await runAudit(root, {});
    assert.equal(queries.length, 4);
    assert.equal(report.vulnerabilityCount, 0);
    assert.deepEqual(report.vulnerabilities, []);
    assert.equal(report.checkedDeps, 4);
  } finally {
    cleanup(root);
  }
});

test("an empty or absent OSV results array is handled", () => {
  const resolved = [{ name: "alpha", version: "1.0.0" }];
  assert.deepEqual(mapOsvResults(resolved, []), []);
  assert.deepEqual(mapOsvResults(resolved, undefined), []);
  assert.equal(assembleVulnerabilityReport(resolved, [], []).vulnerabilityCount, 0);
});

test("an OSV response longer than the query list never invents packages", () => {
  const resolved = [{ name: "alpha", version: "1.0.0" }];
  const rows = mapOsvResults(resolved, [
    { vulns: [{ id: "A" }] },
    { vulns: [{ id: "B" }] },
    { vulns: [{ id: "C" }] },
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, "alpha");
  assert.equal(rows[0].id, "A");
});

test("the same id on two packages stays two findings", () => {
  const resolved = [
    { name: "alpha", version: "1.0.0" },
    { name: "bravo", version: "2.0.0" },
  ];
  const rows = mapOsvResults(resolved, [{ vulns: [{ id: "SHARED" }] }, { vulns: [{ id: "SHARED" }] }]);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => r.name), ["alpha", "bravo"]);
});

// ─── multiple findings ──────────────────────────────────────────────────────

test("one package with several vulnerabilities: all attributed to it", async () => {
  const root = makeProject(DEPS, { alpha: "1.0.0", bravo: "2.0.0", charlie: "3.0.0", delta: "4.0.0" });
  try {
    const ids = ["GHSA-a1", "GHSA-a2", "GHSA-a3"];
    const { queries, report } = await runAudit(root, { alpha: ids });

    assert.equal(report.vulnerabilityCount, 3);
    assertAttribution(report, queries);
    for (const v of report.vulnerabilities) {
      assert.equal(v.name, "alpha");
      assert.equal(v.version, "1.0.0");
    }
    assert.deepEqual(report.vulnerabilities.map((v) => v.id).sort(), ids);
  } finally {
    cleanup(root);
  }
});

test("several packages with distinct vulnerabilities each keep their own", async () => {
  const root = makeProject(DEPS, { alpha: "1.0.0", bravo: "2.0.0", charlie: "3.0.0", delta: "4.0.0" });
  try {
    const { queries, report } = await runAudit(root, {
      alpha: ["GHSA-a1", "GHSA-a2"],
      bravo: [VULN_BRAVO],
      charlie: ["GHSA-c1"],
      delta: [],
    });

    assert.equal(report.vulnerabilityCount, 4);
    assertAttribution(report, queries);

    const expected = {
      "GHSA-a1": ["alpha", "1.0.0"],
      "GHSA-a2": ["alpha", "1.0.0"],
      [VULN_BRAVO]: ["bravo", "2.0.0"],
      "GHSA-c1": ["charlie", "3.0.0"],
    };
    for (const v of report.vulnerabilities) {
      assert.deepEqual([v.name, v.version], expected[v.id]);
    }
    assert.ok(!report.vulnerabilities.some((v) => v.name === "delta"));
  } finally {
    cleanup(root);
  }
});

// ─── the failure observed in the field ──────────────────────────────────────

test("regression: an uninstalled first dep must not shift a finding onto itself", async () => {
  const root = makeProject({ "uninstalled-pkg-xyz": "1.0.0", lodash: "4.17.15" }, { lodash: "4.17.15" });
  try {
    const { declared, resolved, skipped, queries, report } = await runAudit(root, {
      "uninstalled-pkg-xyz": ["GHSA-should-never-appear"],
      lodash: ["GHSA-35jh-r3h4-6jhm"],
    });

    assert.equal(declared.length, 2);
    assert.equal(resolved.length, 1);
    assert.equal(queries.length, 1);
    assert.deepEqual(queries[0], { package: { ecosystem: "npm", name: "lodash" }, version: "4.17.15" });
    assert.deepEqual(skipped.map((s) => s.name), ["uninstalled-pkg-xyz"]);

    assert.equal(report.vulnerabilityCount, 1);
    assert.equal(report.vulnerabilities[0].name, "lodash");
    assert.equal(report.vulnerabilities[0].version, "4.17.15");
    assert.equal(report.vulnerabilities[0].id, "GHSA-35jh-r3h4-6jhm");
    assertAttribution(report, queries);

    for (const v of report.vulnerabilities) {
      assert.equal(typeof v.version, "string");
    }
  } finally {
    cleanup(root);
  }
});

// ─── resolution ─────────────────────────────────────────────────────────────

test("resolveInstalled reads the installed version, and null when absent", async () => {
  const root = makeProject({ alpha: "^1.0.0" }, { alpha: "1.2.3" });
  try {
    assert.equal(await resolveInstalled(root, "alpha"), "1.2.3");
    assert.equal(await resolveInstalled(root, "nope"), null);
  } finally {
    cleanup(root);
  }
});

test("a dep declared but not installed is reported in skipped with a reason", async () => {
  const root = makeProject({ alpha: "^1.0.0", ghost: "^9.9.9" }, { alpha: "1.0.0" });
  try {
    const { resolved, skipped } = await resolvePackages(root);
    assert.deepEqual(resolved.map((d) => d.name), ["alpha"]);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].name, "ghost");
    assert.equal(skipped[0].range, "^9.9.9");
    assert.match(skipped[0].reason, /not installed/);
  } finally {
    cleanup(root);
  }
});

test("no package.json produces the actionable error", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-audit-empty-"));
  try {
    await assert.rejects(() => resolvePackages(root), /package\.json/);
  } finally {
    cleanup(root);
  }
});

// ─── outdated comparison ────────────────────────────────────────────────────

test("audit_outdated only compares resolved packages", async () => {
  const resolved = [
    { name: "alpha", version: "1.0.0", range: "^1.0.0" },
    { name: "bravo", version: "2.0.0", range: "^2.0.0" },
  ];
  const calls = [];
  const fakeFetch = async (url) => {
    calls.push(url);
    return { ok: true, json: async () => ({ version: "2.0.0" }) };
  };
  const outdated = await checkOutdated(resolved, fakeFetch);
  assert.equal(calls.length, 2);
  assert.deepEqual(outdated, [{ name: "alpha", current: "1.0.0", latest: "2.0.0", level: "major" }]);
});

test("diffLevel classifies major/minor/patch", () => {
  assert.equal(diffLevel("1.0.0", "2.0.0"), "major");
  assert.equal(diffLevel("1.0.0", "1.1.0"), "minor");
  assert.equal(diffLevel("1.0.0", "1.0.1"), "patch");
  assert.equal(diffLevel("^0.21.1", "1.0.0"), "major", "range prefixes must be tolerated");
});

test("severityOf maps CVSS scores and database severities", () => {
  assert.equal(severityOf({ database_specific: { severity: "HIGH" } }), "HIGH");
  assert.equal(severityOf({ severity: [{ score: "9.8" }] }), "CRITICAL");
  assert.equal(severityOf({ severity: [{ score: "7.5" }] }), "HIGH");
  assert.equal(severityOf({ severity: [{ score: "5.0" }] }), "MEDIUM");
  assert.equal(severityOf({ severity: [{ score: "2.0" }] }), "LOW");
  assert.equal(severityOf({}), "UNKNOWN");
});

// ─── output contract ────────────────────────────────────────────────────────

const PRE_EXISTING = ["totalDeps", "checkedDeps", "vulnerabilityCount", "vulnerabilities"];

test("every pre-existing property is still declared and required", () => {
  for (const key of PRE_EXISTING) {
    assert.ok(key in VULNERABILITIES_OUTPUT_SCHEMA.properties, `${key} must remain declared`);
    assert.equal(VULNERABILITIES_OUTPUT_SCHEMA.properties[key].required, true, `${key} must stay required`);
  }
});

test("`skipped` is additive, not a breaking required field", () => {
  assert.ok("skipped" in VULNERABILITIES_OUTPUT_SCHEMA.properties, "skipped must be declared");
  assert.equal(VULNERABILITIES_OUTPUT_SCHEMA.properties.skipped.type, "array");
  assert.equal(VULNERABILITIES_OUTPUT_SCHEMA.properties.skipped.required, undefined);
  assert.ok(!("required" in VULNERABILITIES_OUTPUT_SCHEMA), "no top-level required array may be introduced");
});

test("the top level permits the added field while items stay strict", () => {
  // additionalProperties:false at the top level would make ANY added field
  // breaking for a consumer holding the previous schema.
  assert.notEqual(VULNERABILITIES_OUTPUT_SCHEMA.additionalProperties, false);
  assert.equal(VULNERABILITIES_OUTPUT_SCHEMA.properties.vulnerabilities.items.additionalProperties, false);
  assert.equal(VULNERABILITIES_OUTPUT_SCHEMA.properties.skipped.items.additionalProperties, false);
});

test("audit_outdated schema is unchanged", () => {
  assert.equal(OUTDATED_OUTPUT_SCHEMA.required, undefined);
  assert.deepEqual(Object.keys(OUTDATED_OUTPUT_SCHEMA.properties).sort(), ["outdated", "outdatedCount"]);
  for (const key of ["name", "current", "latest", "level"]) {
    assert.equal(OUTDATED_OUTPUT_SCHEMA.properties.outdated.items.properties[key].required, true);
  }
});

test("renderer reports skipped only when non-empty", () => {
  const base = { totalDeps: 4, checkedDeps: 4, vulnerabilityCount: 0, vulnerabilities: [] };

  const clean = renderVulnerabilities({ ...base, skipped: [] });
  assert.match(clean, /4\/4 /);
  assert.ok(!clean.includes("跳过"), "a fully-resolved project must not mention skipping");

  const withSkipped = renderVulnerabilities({
    ...base,
    totalDeps: 6,
    checkedDeps: 4,
    skipped: [
      { name: "ghost-a", range: "^1.0.0", reason: "not installed" },
      { name: "ghost-b", range: "^2.0.0", reason: "not installed" },
    ],
  });
  assert.match(withSkipped, /4\/6 /);
  assert.match(withSkipped, /ghost-a, ghost-b/);
});

test("renderer tolerates a payload that predates `skipped`", () => {
  const text = renderVulnerabilities({
    totalDeps: 1,
    checkedDeps: 1,
    vulnerabilityCount: 0,
    vulnerabilities: [],
  });
  assert.match(text, /1\/1 /);
});

test("renderer includes name, version, severity and fix", () => {
  const text = renderVulnerabilities({
    totalDeps: 1,
    checkedDeps: 1,
    vulnerabilityCount: 1,
    vulnerabilities: [
      {
        name: "lodash",
        version: "4.17.15",
        id: "GHSA-35jh-r3h4-6jhm",
        severity: "HIGH",
        summary: "Command Injection in lodash",
        fixed: "4.17.21",
      },
    ],
    skipped: [],
  });
  assert.match(text, /\[HIGH\] lodash@4\.17\.15/);
  assert.match(text, /GHSA-35jh-r3h4-6jhm/);
  assert.match(text, /4\.17\.21/);
});

test("renderer truncates past 30 vulnerabilities with a count", () => {
  const vulnerabilities = Array.from({ length: 33 }, (_v, i) => ({
    name: `p${i}`,
    version: "1.0.0",
    id: `GHSA-${i}`,
    severity: "LOW",
    summary: "s",
    fixed: "",
  }));
  const text = renderVulnerabilities({
    totalDeps: 33,
    checkedDeps: 33,
    vulnerabilityCount: 33,
    vulnerabilities,
    skipped: [],
  });
  assert.match(text, /3/);
});

test("renderer handles the outdated summary and the empty case", () => {
  const withRows = renderOutdated({
    outdatedCount: 2,
    outdated: [
      { name: "alpha", current: "1.0.0", latest: "2.0.0", level: "major" },
      { name: "bravo", current: "1.0.0", latest: "1.0.1", level: "patch" },
    ],
  });
  assert.match(withRows, /alpha: 1\.0\.0 → 2\.0\.0（major）/);

  const empty = renderOutdated({ outdatedCount: 0, outdated: [] });
  assert.match(empty, /0/);
});
