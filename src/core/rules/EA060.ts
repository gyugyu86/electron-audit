import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { AggregateRule, AggregateRuleContext, Finding, ParsedProjectFile } from '../types.js';

// Known analytics/telemetry SDKs. Deliberately a conservative whitelist of
// CLEAR cases — an ambiguous package (e.g. bare "analytics", or firebase,
// which is mostly used for non-telemetry features) is left out to avoid a
// misleading privacy notice. Exact package names plus scoped prefixes.
const TELEMETRY_EXACT = new Set([
  'react-ga',
  'react-ga4',
  'mixpanel',
  'mixpanel-browser',
  'posthog-js',
  'posthog-node',
  'amplitude-js',
  'universal-analytics',
  'ga-gtag',
  'react-gtm-module',
  'analytics-node',
  'appcenter-analytics',
  'applicationinsights',
]);
const TELEMETRY_SCOPE_PREFIXES = ['@sentry/', '@amplitude/', '@segment/', '@posthog/'];

function isTelemetryPackage(name: string): boolean {
  return TELEMETRY_EXACT.has(name) || TELEMETRY_SCOPE_PREFIXES.some((prefix) => name.startsWith(prefix));
}

const WHY_DANGEROUS =
  "This SDK is an analytics/telemetry tool that sends user behavior/device information to an external server. " +
  "It's not a security vulnerability, but complying with privacy regulations (GDPR, etc.) requires disclosing what " +
  'data is collected and sent, and providing a way to opt out.';

const RECOMMENDATION = `Document what's collected in your privacy policy, and offer opt-in consent (or an opt-out) on first run.
Check that sensitive information (file paths, input content, etc.) isn't riding along in these events.`;

// A telemetry SDK detected in the project — either imported in a source file
// (with a location) or declared in package.json (anchored at the manifest).
interface Detection {
  sdk: string;
  file: string;
  line: number;
}

export const EA060: AggregateRule = {
  id: 'EA060',
  kind: 'aggregate',
  severity: 'info',
  target: 'Analytics/telemetry SDK in use (a privacy notice, not a vulnerability)',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    // One finding per distinct SDK. An import location is preferred (more
    // actionable); a dep-only match falls back to the package.json anchor.
    const bySdk = new Map<string, Detection>();

    for (const detection of collectImportDetections(context.parsedFiles)) {
      if (!bySdk.has(detection.sdk)) {
        bySdk.set(detection.sdk, detection);
      }
    }

    const packageJsonPath = context.project.packageJsonPath ?? 'package.json';
    for (const name of context.project.dependencyNames ?? []) {
      if (isTelemetryPackage(name) && !bySdk.has(name)) {
        bySdk.set(name, { sdk: name, file: packageJsonPath, line: 0 });
      }
    }

    return [...bySdk.values()].map((detection) => ({
      ruleId: 'EA060',
      severity: 'info',
      // Advisory privacy notice, not a certainty-of-vulnerability claim —
      // kept out of the high-confidence tier so it never trips the clean
      // corpus gate as the corpus grows.
      confidence: 'heuristic',
      file: detection.file,
      line: detection.line,
      target: `${detection.sdk} (analytics/telemetry SDK)`,
      whyDangerous: WHY_DANGEROUS,
      recommendation: RECOMMENDATION,
    }));
  },
};

// Walks each parsed file for import/require of a telemetry package and
// records the source string + line. (collectImportBindings drops line info,
// which this rule needs, so it does its own small pass.)
function collectImportDetections(parsedFiles: ParsedProjectFile[]): Detection[] {
  const detections: Detection[] = [];

  for (const { file, ast } of parsedFiles) {
    traverse(ast, {
      ImportDeclaration(path) {
        const source = path.node.source.value;
        if (isTelemetryPackage(source)) {
          detections.push({ sdk: source, file: file.path, line: path.node.loc?.start.line ?? 0 });
        }
      },
      CallExpression(path) {
        if (!t.isIdentifier(path.node.callee) || path.node.callee.name !== 'require') {
          return;
        }
        const arg = path.node.arguments[0];
        if (arg && t.isStringLiteral(arg) && isTelemetryPackage(arg.value)) {
          detections.push({ sdk: arg.value, file: file.path, line: path.node.loc?.start.line ?? 0 });
        }
      },
    });
  }

  return detections;
}
