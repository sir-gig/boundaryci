import { randomUUID } from "node:crypto";
import { redactSecrets } from "./fireworks.js";
import { shouldFail } from "./report.js";
import type { FailThreshold, ReportFinding, ScanReport } from "./types.js";

type FetchLike = typeof fetch;

export interface CloudUploadContext {
  repository: string;
  commitSha: string | null;
  branch: string | null;
  pullRequest: number | null;
  failOn: FailThreshold;
  includeAiInExitCode: boolean;
}

export interface CloudFinding {
  fingerprint: string;
  ruleId: string;
  title: string;
  description: string;
  severity: ReportFinding["severity"];
  confidence: ReportFinding["confidence"];
  source: ReportFinding["source"];
  disposition: ReportFinding["disposition"];
  file: string;
  line: number;
  evidence: string;
  recommendation: string;
  tags: string[];
  waiver: ReportFinding["waiver"];
}

export interface CloudScanPayload {
  schemaVersion: "1.0";
  externalId: string;
  repository: string;
  provider: "github";
  commitSha: string | null;
  branch: string | null;
  pullRequest: number | null;
  outcome: "passed" | "failed";
  failOn: FailThreshold;
  includeAiInExitCode: boolean;
  toolVersion: string;
  scannedAt: string;
  fileCount: number;
  databaseProfile: ScanReport["databaseProfile"];
  semanticReview: ScanReport["semanticReview"];
  summary: ScanReport["summary"];
  findings: CloudFinding[];
}

export interface CloudUploadResult {
  scanId: string;
  dashboardUrl: string | null;
}

function normalizeRepository(value: string): string {
  const repository = value.trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error(
      "Cloud upload requires a repository in owner/name format. Pass --repository or set GITHUB_REPOSITORY.",
    );
  }
  return repository;
}

function optionalText(value: string | null, field: string, maxLength: number): string | null {
  if (value === null || value.trim() === "") return null;
  const normalized = value.trim();
  if (normalized.length > maxLength) {
    throw new Error(`${field} must be at most ${maxLength} characters.`);
  }
  return normalized;
}

function normalizeFilePath(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\//, "");
  const safeParts = normalized.split("/").filter((part) => part && part !== "." && part !== "..");
  if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) {
    return safeParts.at(-1)?.slice(0, 500) || "unknown.sql";
  }
  return safeParts.join("/").slice(0, 500) || "unknown.sql";
}

function redactAndLimit(value: string, maxLength: number): string {
  return redactSecrets(value).slice(0, maxLength);
}

function cloudFinding(finding: ReportFinding): CloudFinding {
  return {
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId.slice(0, 40),
    title: redactAndLimit(finding.title, 180),
    description: redactAndLimit(finding.description, 1_200),
    severity: finding.severity,
    confidence: finding.confidence,
    source: finding.source,
    disposition: finding.disposition,
    file: normalizeFilePath(finding.location.file),
    line: finding.location.line,
    evidence: redactAndLimit(finding.evidence, 800),
    recommendation: redactAndLimit(finding.recommendation, 1_200),
    tags: finding.tags.map((tag) => redactAndLimit(tag, 80)).slice(0, 8),
    waiver: finding.waiver
      ? {
          owner: redactAndLimit(finding.waiver.owner, 160),
          reason: redactAndLimit(finding.waiver.reason, 500),
          expiresOn: finding.waiver.expiresOn,
        }
      : null,
  };
}

export function createCloudScanPayload(
  report: ScanReport,
  context: CloudUploadContext,
  externalId = randomUUID(),
): CloudScanPayload {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(externalId)) {
    throw new Error("Cloud scan externalId must be a UUID.");
  }
  if (
    context.pullRequest !== null &&
    (!Number.isInteger(context.pullRequest) || context.pullRequest < 1)
  ) {
    throw new Error("pullRequest must be a positive integer when supplied.");
  }

  return {
    schemaVersion: "1.0",
    externalId,
    repository: normalizeRepository(context.repository),
    provider: "github",
    commitSha: optionalText(context.commitSha, "commitSha", 128),
    branch: optionalText(context.branch, "branch", 255),
    pullRequest: context.pullRequest,
    outcome: shouldFail(report, context.failOn, context.includeAiInExitCode)
      ? "failed"
      : "passed",
    failOn: context.failOn,
    includeAiInExitCode: context.includeAiInExitCode,
    toolVersion: report.tool.version,
    scannedAt: report.scannedAt,
    fileCount: report.files.length,
    databaseProfile: report.databaseProfile,
    semanticReview: report.semanticReview,
    summary: report.summary,
    findings: report.findings.map(cloudFinding),
  };
}

function validateEndpoint(endpoint: string): string {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error("BOUNDARYCI_CLOUD_URL must be a valid URL.");
  }

  const localHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && localHosts.has(url.hostname))) {
    throw new Error("BoundaryCI Cloud requires HTTPS except when using a localhost endpoint.");
  }
  if (url.username || url.password) {
    throw new Error("BOUNDARYCI_CLOUD_URL must not contain credentials.");
  }
  url.hash = "";
  return url.toString();
}

function validateToken(token: string): string {
  const normalized = token.trim();
  if (!normalized.startsWith("bci_") || normalized.length < 24) {
    throw new Error("BOUNDARYCI_CLOUD_TOKEN is not a valid BoundaryCI ingestion token.");
  }
  return normalized;
}

export async function uploadScanReport(
  endpoint: string,
  token: string,
  payload: CloudScanPayload,
  fetchImplementation: FetchLike = fetch,
): Promise<CloudUploadResult> {
  const response = await fetchImplementation(validateEndpoint(endpoint), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${validateToken(token)}`,
      "Content-Type": "application/json",
      "User-Agent": `boundaryci/${payload.toolVersion}`,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20_000),
  });

  const responseText = (await response.text()).slice(0, 2_000);
  let responsePayload: unknown;
  try {
    responsePayload = responseText ? (JSON.parse(responseText) as unknown) : null;
  } catch {
    responsePayload = null;
  }

  if (!response.ok) {
    const message =
      responsePayload &&
      typeof responsePayload === "object" &&
      typeof (responsePayload as { error?: unknown }).error === "string"
        ? (responsePayload as { error: string }).error
        : `HTTP ${response.status}`;
    throw new Error(`BoundaryCI Cloud upload failed: ${redactAndLimit(message, 300)}`);
  }

  if (!responsePayload || typeof responsePayload !== "object") {
    throw new Error("BoundaryCI Cloud returned an invalid response.");
  }
  const scanId = (responsePayload as { scanId?: unknown }).scanId;
  const dashboardUrl = (responsePayload as { dashboardUrl?: unknown }).dashboardUrl;
  if (typeof scanId !== "string" || scanId.trim() === "") {
    throw new Error("BoundaryCI Cloud returned no scan identifier.");
  }
  if (dashboardUrl !== null && dashboardUrl !== undefined && typeof dashboardUrl !== "string") {
    throw new Error("BoundaryCI Cloud returned an invalid dashboard URL.");
  }

  return {
    scanId,
    dashboardUrl: typeof dashboardUrl === "string" && dashboardUrl ? dashboardUrl : null,
  };
}
