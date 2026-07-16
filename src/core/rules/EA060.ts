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
  '이 SDK는 사용자 행동/기기 정보를 외부 서버로 전송하는 애널리틱스·텔레메트리 용도입니다. 보안 취약점은 아니지만, ' +
  '어떤 데이터가 수집·전송되는지 사용자에게 고지하고 옵트아웃 수단을 제공해야 프라이버시 규정(GDPR 등)에 부합합니다.';

const RECOMMENDATION = `수집 항목을 개인정보 처리방침에 명시하고, 최초 실행 시 동의(opt-in) 또는 옵트아웃을 제공하세요.
민감 정보(파일 경로, 입력 내용 등)가 이벤트에 실려 나가지 않는지 점검하세요.`;

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
  target: '애널리틱스/텔레메트리 SDK 사용 (프라이버시 고지 목적, 취약점 아님)',
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
      target: `${detection.sdk} (애널리틱스/텔레메트리 SDK)`,
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
