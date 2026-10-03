// dsh-dependency-audit — 依赖安全审计（DeepSeek Harness）。
// 扫描项目依赖：① 通过 OSV.dev 查询已知漏洞；② 对比 npm registry 检测过期依赖。
// 需要网络（OSV.dev 与 npm registry）。纯 Node，无其它外部服务。
import { defineTool } from "@deepseek-ai/dsh-tools";
import {
  assembleVulnerabilityReport,
  buildOsvQueries,
  checkOutdated,
  fetchVulnDetail,
  mapOsvResults,
  osvQuery,
  OUTDATED_OUTPUT_SCHEMA,
  renderOutdated,
  renderVulnerabilities,
  resolvePackages,
  VULNERABILITIES_OUTPUT_SCHEMA,
} from "./core.js";

const name = "依赖安全审计";
const inject = ["tools"];

async function apply(ctx, _config) {
  ctx.tools.register(defineTool({
    name: "audit_vulnerabilities",
    description:
      "扫描项目依赖的已知安全漏洞：读取 package.json 的 dependencies/devDependencies 及其已安装版本，批量查询 OSV.dev 漏洞数据库，返回每个受影响依赖的漏洞 ID、严重级、摘要与修复版本。未安装（无法解析版本）的依赖不会被查询，会在 skipped 中列出。用于发布前/日常安全自查。`root` 传项目根目录，默认当前工作目录。需联网访问 osv.dev。",
    parameters: {
      root: { type: "string", description: "项目根目录（含 package.json 与 node_modules）。默认当前工作目录。" },
    },
    output: {
      schema: VULNERABILITIES_OUTPUT_SCHEMA,
      render: (_args, value) => [{ type: "text", text: renderVulnerabilities(value) }],
    },
    execute: async (args) => {
      const root = args.root || process.cwd();
      // Resolve once. `resolved` is both the query list and the attribution
      // list, so an unresolved dependency can never shift an index.
      const { declared, resolved, skipped } = await resolvePackages(root);
      const results = await osvQuery(buildOsvQueries(resolved));

      // `mapped` derives from the same `resolved` array the queries came from,
      // and `details` is built by mapping over that exact list, so the three
      // stay index-aligned by construction.
      const mapped = mapOsvResults(resolved, results);
      const details = await Promise.all(mapped.map((row) => fetchVulnDetail(row.id)));

      return {
        ...assembleVulnerabilityReport(resolved, results, details),
        totalDeps: declared.length,
        checkedDeps: resolved.length,
        skipped,
      };
    },
  }));

  ctx.tools.register(defineTool({
    name: "audit_outdated",
    description:
      "检测项目依赖是否过期：对比已安装版本与 npm registry 最新版，返回每个过期依赖的当前版本、最新版本与升级幅度（major/minor/patch）。用于判断哪些依赖需要升级。未安装的依赖会被跳过。`root` 传项目根目录，默认当前工作目录。需联网访问 npm registry。",
    parameters: {
      root: { type: "string", description: "项目根目录。默认当前工作目录。" },
    },
    output: {
      schema: OUTDATED_OUTPUT_SCHEMA,
      render: (_args, value) => [{ type: "text", text: renderOutdated(value) }],
    },
    execute: async (args) => {
      const root = args.root || process.cwd();
      const { resolved } = await resolvePackages(root);
      const outdated = await checkOutdated(resolved);
      return { outdatedCount: outdated.length, outdated };
    },
  }));
}

export { apply, inject, name };
