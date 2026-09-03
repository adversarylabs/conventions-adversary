#!/usr/bin/env node

import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  Adversary,
  Severity,
  formatOpinion,
  resolveModelCitation,
  type EvidenceInput,
  type ModelRepositoryCitation,
  type RuleContext,
} from "@adversarylabs/sdk";
import { DISCOVERY_PROMPT, VERIFICATION_PROMPT } from "./prompts.js";

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

const verifiedSchema: Record<string, unknown> = structuredClone(findingSchema);
const verifiedArray = (verifiedSchema.properties as Record<string, unknown>).findings as Record<string, unknown>;
const verifiedItem = verifiedArray.items as Record<string, unknown>;
const verifiedProperties = verifiedItem.properties as Record<string, Record<string, unknown>>;
verifiedProperties.confidence = { enum: ["high"] };

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
  app.rule("conventions.discover-and-verify", reviewConventions);
  return app;
}

async function reviewConventions(ctx: RuleContext): Promise<void> {
  const changedFiles = [...(ctx.change?.changedFiles ?? [])];
  ctx.summary.files_scanned = changedFiles.length;
  const graphHints = buildGraphHints(ctx, changedFiles);
  const discovery = await ctx.model.review<ConventionOutput>({
    prompt: DISCOVERY_PROMPT,
    input: { change: ctx.change, graphHints },
    schema: findingSchema,
    budget: { maximumOutputTokens: 16_000, timeoutMs: 600_000 },
    tools: repositoryTools,
  });
  const candidates = discovery.output.findings.map((finding) => ({
    ...finding,
    evidence: materializeEvidence(finding.evidence, discovery.citations),
  }));
  const verification = await ctx.model.review<ConventionOutput>({
    prompt: VERIFICATION_PROMPT,
    input: { change: ctx.change, candidates },
    schema: verifiedSchema,
    budget: { maximumOutputTokens: 12_000, timeoutMs: 600_000 },
    tools: repositoryTools,
  });

  const accepted: ConventionFinding[] = [];
  for (const finding of verification.output.findings) {
    const evidence = finding.evidence
      .map((claim) => evidenceInput(claim, verification.citations))
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
      tags: ["code-review", "repository-convention", finding.basis, "independently-verified"],
      metadata: { basis: finding.basis, scope: finding.scope, verificationPasses: 1 },
    });
  }

  const risk = accepted.reduce<Risk | "none">(
    (best, finding) => riskRank(finding.severity) > riskRank(best) ? finding.severity : best,
    "none",
  );
  ctx.review.assessment({
    risk,
    summary: accepted.length === 0
      ? "No repository-convention deviation survived independent verification."
      : `${accepted.length} repository-convention deviation${accepted.length === 1 ? "" : "s"} survived independent verification.`,
  });
  ctx.review.opinion(formatOpinion({
    ship: accepted.length === 0,
    ...(accepted.length === 0 ? {} : { concern: "the verified repository-convention findings" }),
    remainingCount: accepted.length,
    change: ctx.change,
  }));
}

function materializeEvidence(
  claims: EvidenceClaim[],
  citations: readonly ModelRepositoryCitation[] | undefined,
): unknown[] {
  return claims.flatMap((claim) => {
    const citation = resolveModelCitation(citations, claim.citationId, claim.line);
    if (citation === undefined) return [];
    return [{
      path: citation.path,
      line: claim.line,
      detail: claim.detail,
      excerpt: excerptAt(citation, claim.line),
    }];
  });
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
