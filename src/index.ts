#!/usr/bin/env node

import { lstat, readFile, realpath } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Adversary,
  Severity,
  formatOpinion,
  isChangedLine,
  resolveModelCitation,
  type EvidenceInput,
  type ModelRepositoryCitation,
  type RuleContext,
} from "@adversarylabs/sdk";
import {
  INFERRED_AUDIT_PROMPT,
  INVENTORY_PROMPT,
  ERROR_AUDIT_PROMPT,
  MECHANICAL_AUDIT_PROMPT,
  STRUCTURAL_AUDIT_PROMPT,
} from "./prompts.js";

type Risk = "low" | "medium" | "high" | "critical";
type Basis = "declared" | "inferred";

interface EvidenceClaim {
  citationId: string;
  line: number;
  detail: string;
}

interface ConventionFinding {
  id: string;
  title: string;
  basis: Basis;
  scope: string;
  severity: Risk;
  confidence: "medium" | "high";
  convention: string;
  deviation: string;
  impact: string;
  fix: string;
  evidence: EvidenceClaim[];
}

interface ConventionOutput {
  findings: ConventionFinding[];
}

interface ContractInventoryOutput {
  rules: Array<{
    id: string;
    title: string;
    sourcePath: string;
    scope: string;
    requirement: string;
    prohibitedExamples: string[];
  }>;
}

const findingSchema: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id", "title", "basis", "scope", "severity", "confidence",
          "convention", "deviation", "impact", "fix", "evidence",
        ],
        properties: {
          id: { type: "string", minLength: 1, maxLength: 100 },
          title: { type: "string", minLength: 8, maxLength: 160 },
          basis: { enum: ["declared", "inferred"] },
          scope: { type: "string", minLength: 2, maxLength: 300 },
          severity: { enum: ["low", "medium", "high", "critical"] },
          confidence: { enum: ["medium", "high"] },
          convention: { type: "string", minLength: 20, maxLength: 2_000 },
          deviation: { type: "string", minLength: 20, maxLength: 2_000 },
          impact: { type: "string", minLength: 10, maxLength: 1_500 },
          fix: { type: "string", minLength: 10, maxLength: 1_500 },
          evidence: {
            type: "array",
            minItems: 2,
            maxItems: 10,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["citationId", "line", "detail"],
              properties: {
                citationId: { type: "string", minLength: 1, maxLength: 120 },
                line: { type: "integer", minimum: 1 },
                detail: { type: "string", minLength: 5, maxLength: 800 },
              },
            },
          },
        },
      },
    },
  },
};

const contractInventorySchema: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["rules"],
  properties: {
    rules: {
      type: "array",
      maxItems: 120,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "title", "sourcePath", "scope", "requirement", "prohibitedExamples"],
        properties: {
          id: { type: "string", minLength: 1, maxLength: 100 },
          title: { type: "string", minLength: 3, maxLength: 200 },
          sourcePath: { type: "string", minLength: 1, maxLength: 500 },
          scope: { type: "string", minLength: 2, maxLength: 500 },
          requirement: { type: "string", minLength: 10, maxLength: 2_000 },
          prohibitedExamples: {
            type: "array",
            maxItems: 20,
            items: { type: "string", minLength: 1, maxLength: 500 },
          },
        },
      },
    },
  },
};

const repositoryTools = {
  repository: {
    exclude: [
      "**/*.lock", "**/*.min.js", "**/*.map", "**/generated/**",
      "**/vendor/**", "**/fixtures/**", "**/testdata/**",
    ],
    maxRounds: 12,
    maxToolCalls: 80,
    maxTotalBytes: 720_000,
    maxBytesPerRead: 64_000,
    maxLinesPerRead: 800,
    directoryPageSize: 300,
    planningTimeoutMs: 180_000,
  },
} as const;

export function createApp(): Adversary {
  const app = new Adversary({
    name: "review/conventions",
    version: "0.0.1",
    review: { minimumConfidence: "medium" },
  });
  app.rule("conventions.coverage", reviewConventions);
  return app;
}

async function reviewConventions(ctx: RuleContext): Promise<void> {
  const changedFiles = [...(ctx.change?.changedFiles ?? [])];
  ctx.summary.files_scanned = changedFiles.length;
  const graphHints = buildGraphHints(ctx, changedFiles);
  const conventionSourceHints = await buildConventionSourceHints(ctx, changedFiles);
  const declaredContractSources = await loadDeclaredContractSources(ctx, conventionSourceHints);
  const changedSourcePreviews = boundChangedSources(await ctx.loadInScopeSources({
    limit: 100,
    maxBytes: 32_000,
  }));
  const declaredContractRules = declaredContractSources.length === 0
    ? []
    : (await ctx.model.review<ContractInventoryOutput>({
      prompt: INVENTORY_PROMPT,
      input: { sources: declaredContractSources },
      schema: contractInventorySchema,
      budget: { maximumOutputTokens: 8_000, timeoutMs: 180_000 },
    })).output.rules;
  const structuralRules = filterContractRules(declaredContractRules, [
    "schema", "validat", "architect", "depend", "boundary", "compatib", "export", "api",
  ]);
  const errorRules = filterContractRules(declaredContractRules, [
    "error", "exception", "throw", "status", "code", "context",
  ]);
  const mechanicalRules = filterContractRules(declaredContractRules, [
    "format", "quote", "test", "vitest", "jest", "naming", "lint", "build", "file", "suffix",
  ]);
  const inferredGroups = chunk(changedSourcePreviews.map((source) => source.path), 2);
  const inferredRequests = inferredGroups.flatMap((focusPaths, groupIndex) =>
    ["producer-first", "consumer-first"].map((traceStrategy, strategyIndex) => ({
      lane: `inferred-${groupIndex * 2 + strategyIndex + 1}`,
      review: ctx.model.review<ConventionOutput>({
        prompt: INFERRED_AUDIT_PROMPT,
        input: {
          change: ctx.change,
          focusPaths,
          traceStrategy,
          changedSourcePreviews: changedSourcePreviews.filter((source) => focusPaths.includes(source.path)),
          graphHints: graphHints.filter((hint) => focusPaths.includes(graphHintPath(hint))),
        },
        schema: findingSchema,
        budget: { maximumOutputTokens: 8_000, timeoutMs: 600_000 },
        tools: repositoryTools,
      }),
    })));
  const auditRequests = [
    { lane: "structural", review: ctx.model.review<ConventionOutput>({
      prompt: STRUCTURAL_AUDIT_PROMPT,
      input: { change: ctx.change, conventionSourceHints, declaredContractRules: structuralRules, changedSourcePreviews, graphHints },
      schema: findingSchema,
      budget: { maximumOutputTokens: 12_000, timeoutMs: 600_000 },
      tools: repositoryTools,
    }) },
    { lane: "errors", review: ctx.model.review<ConventionOutput>({
      prompt: ERROR_AUDIT_PROMPT,
      input: { change: ctx.change, conventionSourceHints, declaredContractRules: errorRules, changedSourcePreviews, graphHints },
      schema: findingSchema,
      budget: { maximumOutputTokens: 8_000, timeoutMs: 600_000 },
      tools: repositoryTools,
    }) },
    { lane: "mechanical", review: ctx.model.review<ConventionOutput>({
      prompt: MECHANICAL_AUDIT_PROMPT,
      input: { change: ctx.change, conventionSourceHints, declaredContractRules: mechanicalRules, changedSourcePreviews, graphHints },
      schema: findingSchema,
      budget: { maximumOutputTokens: 12_000, timeoutMs: 600_000 },
      tools: repositoryTools,
    }) },
    ...inferredRequests,
  ];
  const settledAudits = await Promise.allSettled(auditRequests.map((request) => request.review));
  const failedLanes: string[] = [];
  const discoveries = settledAudits.flatMap((result, index) => {
    if (result.status === "rejected") {
      failedLanes.push(auditRequests[index]?.lane ?? `lane-${index + 1}`);
      return [];
    }
    return [{ lane: auditRequests[index]?.lane ?? `lane-${index + 1}`, discovery: result.value }];
  });
  if (failedLanes.length > 0) {
    ctx.review.observe({
      key: "conventions.partial-review",
      summary: `${failedLanes.length} independent convention review lane${failedLanes.length === 1 ? "" : "s"} failed; successful lanes were preserved.`,
      metadata: { failedLanes },
    });
  }
  const scopedCandidates = dedupeCandidates([
    ...discoveries.flatMap(({ lane, discovery }) =>
      withLane(lane, discovery.output.findings, discovery.citations)),
  ].filter((candidate) => candidate.finding.evidence.some((claim) => {
    const citation = resolveModelCitation(candidate.citations, claim.citationId, claim.line);
    return citation !== undefined && isChangedLine(ctx.change, citation.path, claim.line);
  })), ctx);
  if (scopedCandidates.length === 0) {
    recordAssessment(ctx, [], changedFiles.length);
    return;
  }
  const accepted: ConventionFinding[] = [];
  for (const { finding, citations } of scopedCandidates) {
    const evidence = finding.evidence
      .map((claim) => evidenceInput(claim, citations))
      .filter((item): item is EvidenceInput => item !== undefined);
    if (evidence.length < 2) continue;
    accepted.push(finding);
    ctx.finding({
      id: `conventions.${safeID(finding.id)}`,
      ruleId: `conventions.${finding.basis}`,
      title: finding.title,
      category: "repository-convention",
      severity: finding.severity as Severity,
      confidence: finding.confidence,
      summary: `${finding.deviation} Convention: ${finding.convention}`,
      whyItMatters: finding.impact,
      impact: finding.impact,
      evidence,
      recommendation: finding.fix,
      remediation: { complexity: "small" },
      tags: ["code-review", "repository-convention", finding.basis, "changed-line-verified"],
      metadata: { basis: finding.basis, scope: finding.scope, changedLineVerified: true },
    });
  }

  recordAssessment(ctx, accepted, changedFiles.length);
}

interface ScopedCandidate {
  finding: ConventionFinding;
  citations: readonly ModelRepositoryCitation[] | undefined;
}

function withLane(
  lane: string,
  findings: ConventionFinding[],
  citations: readonly ModelRepositoryCitation[] | undefined,
): ScopedCandidate[] {
  return findings.map((finding) => ({
    finding: { ...finding, id: `${lane}-${finding.id}` },
    citations,
  }));
}

function dedupeCandidates(candidates: ScopedCandidate[], ctx: RuleContext): ScopedCandidate[] {
  const kept: ScopedCandidate[] = [];
  for (const candidate of candidates) {
    const duplicate = kept.some((existing) =>
      nearbyChangedEvidence(existing, candidate, ctx) &&
      tokenSimilarity(findingText(existing.finding), findingText(candidate.finding)) >= 0.2);
    if (!duplicate) kept.push(candidate);
  }
  return kept;
}

function nearbyChangedEvidence(left: ScopedCandidate, right: ScopedCandidate, ctx: RuleContext): boolean {
  const locations = (candidate: ScopedCandidate) => candidate.finding.evidence.flatMap((claim) => {
    const citation = resolveModelCitation(candidate.citations, claim.citationId, claim.line);
    if (citation === undefined || !isChangedLine(ctx.change, citation.path, claim.line)) return [];
    return [{ path: citation.path.replace(/^\.\//, ""), line: claim.line }];
  });
  const leftLocations = locations(left);
  return locations(right).some((rightLocation) => leftLocations.some((leftLocation) =>
    leftLocation.path === rightLocation.path && Math.abs(leftLocation.line - rightLocation.line) <= 2));
}

function findingText(finding: ConventionFinding): string {
  return `${finding.title} ${finding.convention} ${finding.deviation}`;
}

function tokenSimilarity(left: string, right: string): number {
  const ignored = new Set(["the", "a", "an", "and", "or", "to", "of", "in", "for", "with", "this", "that", "new"]);
  const tokens = (value: string) => new Set(value.toLowerCase().split(/[^a-z0-9]+/)
    .filter((token) => token.length > 2 && !ignored.has(token)));
  const leftTokens = tokens(left);
  const rightTokens = tokens(right);
  const intersection = [...leftTokens].filter((token) => rightTokens.has(token)).length;
  const union = new Set([...leftTokens, ...rightTokens]).size;
  return union === 0 ? 0 : intersection / union;
}

function chunk<T>(items: T[], size: number): T[][] {
  const groups: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    groups.push(items.slice(index, index + size));
  }
  return groups;
}

function filterContractRules(
  rules: ContractInventoryOutput["rules"],
  keywords: string[],
): ContractInventoryOutput["rules"] {
  return rules.filter((rule) => {
    const searchable = `${rule.title} ${rule.scope} ${rule.requirement}`.toLowerCase();
    return keywords.some((keyword) => searchable.includes(keyword));
  });
}

function graphHintPath(hint: unknown): string {
  if (typeof hint !== "object" || hint === null || !("path" in hint)) return "";
  return typeof hint.path === "string" ? hint.path : "";
}

function boundChangedSources(
  sources: Array<{ path: string; content: string }>,
): Array<{ path: string; content: string }> {
  const result: Array<{ path: string; content: string }> = [];
  let remainingBytes = 160_000;
  for (const source of sources) {
    if (remainingBytes <= 0) break;
    const bounded = Buffer.from(source.content).subarray(0, remainingBytes).toString("utf8");
    result.push({ path: source.path, content: bounded });
    remainingBytes -= Buffer.byteLength(bounded);
  }
  return result;
}

function recordAssessment(ctx: RuleContext, accepted: ConventionFinding[], filesScanned: number): void {
  ctx.summary.files_scanned = filesScanned;

  const risk = accepted.reduce<Risk | "none">(
    (best, finding) => riskRank(finding.severity) > riskRank(best) ? finding.severity : best,
    "none",
  );
  ctx.review.assessment({
    risk,
    summary: accepted.length === 0
      ? "No evidence-backed repository-convention deviation was found."
      : `${accepted.length} evidence-backed repository-convention deviation${accepted.length === 1 ? "" : "s"} found.`,
  });
  ctx.review.opinion(formatOpinion({
    ship: accepted.length === 0,
    ...(accepted.length === 0 ? {} : { concern: "the evidence-backed repository-convention findings" }),
    remainingCount: accepted.length,
    change: ctx.change,
  }));
}

async function buildConventionSourceHints(ctx: RuleContext, changedFiles: string[]): Promise<string[]> {
  const paths = await ctx.rglob("*");
  return paths
    .filter((path) => isConventionSource(path) && appliesToChangedFiles(path, changedFiles))
    .sort((left, right) =>
      contractSourcePriority(left) - contractSourcePriority(right) ||
      pathDepth(right) - pathDepth(left) ||
      left.localeCompare(right))
    .slice(0, 120);
}

function isConventionSource(path: string): boolean {
  const normalized = path.toLowerCase();
  const name = normalized.split("/").at(-1) ?? normalized;
  return name === "agents.md" || name === "claude.md" || name.startsWith("contributing") ||
    name.startsWith("readme") || name === ".editorconfig" || name === "biome.json" ||
    name.startsWith("eslint.config.") || name === "pyproject.toml" || name === "cargo.toml" ||
    name === "go.mod" || name === "makefile" || normalized.includes("/.cursor/rules/") ||
    normalized.startsWith(".cursor/rules/") || normalized.startsWith(".github/workflows/");
}

function appliesToChangedFiles(path: string, changedFiles: string[]): boolean {
  const normalized = path.toLowerCase();
  if (!path.includes("/") || normalized.startsWith(".cursor/rules/")) return true;
  if (normalized.startsWith(".github/workflows/")) {
    return changedFiles.some((changedPath) => changedPath.startsWith(".github/workflows/"));
  }
  const directory = path.slice(0, path.lastIndexOf("/"));
  return changedFiles.some((changedPath) => changedPath.startsWith(directory + "/"));
}

function pathDepth(path: string): number {
  return path.split("/").length - 1;
}

interface DeclaredContractSource {
  path: string;
  content: string;
}

async function loadDeclaredContractSources(
  ctx: RuleContext,
  hints: string[],
): Promise<DeclaredContractSource[]> {
  const repositoryRoot = await realpath(ctx.repoPath);
  const prioritized = [...hints].sort((left, right) =>
    contractSourcePriority(left) - contractSourcePriority(right) || left.localeCompare(right));
  const result: DeclaredContractSource[] = [];
  let remainingBytes = 96_000;

  for (const path of prioritized) {
    if (result.length >= 10 || remainingBytes <= 0) break;
    const requested = resolve(repositoryRoot, path);
    if (requested !== repositoryRoot && !requested.startsWith(repositoryRoot + sep)) continue;
    const info = await lstat(requested).catch(() => undefined);
    if (info === undefined || !info.isFile() || info.isSymbolicLink()) continue;
    const actual = await realpath(requested).catch(() => undefined);
    if (actual === undefined || (actual !== repositoryRoot && !actual.startsWith(repositoryRoot + sep))) continue;
    const raw = await readFile(actual);
    const bounded = raw.subarray(0, Math.min(raw.length, 24_000, remainingBytes));
    result.push({ path, content: bounded.toString("utf8") });
    remainingBytes -= bounded.length;
  }
  return result;
}

function contractSourcePriority(path: string): number {
  const normalized = path.toLowerCase();
  if (normalized.endsWith("/agents.md") || normalized === "agents.md" ||
      normalized.endsWith("/claude.md") || normalized === "claude.md") return 0;
  if (normalized.includes("/.cursor/rules/") || normalized.startsWith(".cursor/rules/")) return 1;
  if (normalized.includes("contributing")) return 2;
  if (normalized.endsWith(".editorconfig") || normalized.endsWith("biome.json") ||
      normalized.includes("eslint.config") || normalized.endsWith("pyproject.toml")) return 3;
  if (normalized.endsWith("package.json") || normalized.endsWith("cargo.toml") ||
      normalized.endsWith("go.mod") || normalized.endsWith("makefile")) return 4;
  if (normalized.includes("readme")) return 5;
  if (normalized.includes("/.github/workflows/") || normalized.startsWith(".github/workflows/")) return 7;
  return 6;
}

function evidenceInput(
  claim: EvidenceClaim,
  citations: readonly ModelRepositoryCitation[] | undefined,
): EvidenceInput | undefined {
  const citation = resolveModelCitation(citations, claim.citationId, claim.line);
  if (citation === undefined) return undefined;
  return {
    location: { file: citation.path, line: claim.line },
    message: claim.detail,
    snippet: excerptAt(citation, claim.line),
    data: { citationId: claim.citationId },
  };
}

function excerptAt(citation: ModelRepositoryCitation, line: number): string {
  const offset = line - citation.startLine;
  return citation.content.split(/\r?\n/).slice(Math.max(0, offset - 1), offset + 2).join("\n").slice(0, 600);
}

function buildGraphHints(ctx: RuleContext, changedFiles: string[]): unknown[] {
  if (ctx.repoGraph === null) return [];
  return changedFiles.slice(0, 40).map((path) => {
    const symbols = ctx.repoGraph?.symbols({ path, limit: 12 }).items ?? [];
    return {
      path,
      symbols: symbols.map((symbol) => ({ name: symbol.name, kind: symbol.kind, line: symbol.startLine })),
      imports: ctx.repoGraph?.importsOf(path, undefined, 12).items.map((edge) => edge.toPath ?? edge.unresolvedTarget) ?? [],
      importers: ctx.repoGraph?.importersOf(path, undefined, 12).items.map((edge) => edge.fromPath) ?? [],
      tests: ctx.repoGraph?.relatedTests({ path, limit: 12 }).items.map((link) => link.testPath) ?? [],
    };
  });
}

function safeID(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "finding";
}

function riskRank(value: Risk | "none"): number {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[value];
}

async function runIfDirect(): Promise<void> {
  if (process.argv[1] !== undefined && (await realpath(process.argv[1])) === (await realpath(fileURLToPath(import.meta.url)))) {
    await createApp().runFromEnvironment();
  }
}

void runIfDirect();
