import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';

// Config files electron-builder reads. The JSON ones we can parse and
// inspect; the others (YAML/JS/TOML) we can't without extra parsers, so a
// project whose signing config lives ONLY in one of those is left alone
// (we can't verify absence → we don't claim it).
const PARSEABLE_CONFIG_FILES = ['electron-builder.json', 'electron-builder.json5'];
const UNPARSEABLE_CONFIG_FILES = [
  'electron-builder.yml',
  'electron-builder.yaml',
  'electron-builder.js',
  'electron-builder.cjs',
  'electron-builder.ts',
  'electron-builder.toml',
];

const WHY_DANGEROUS =
  '코드 서명 설정이 없으면 배포 산출물이 서명되지 않아, 사용자 OS가 "확인되지 않은 개발자" 경고를 띄우고 ' +
  '자동 업데이트 무결성 검증도 약해집니다. 서명되지 않은 빌드는 중간자 변조를 탐지하기 어렵습니다.';

const RECOMMENDATION = `electron-builder 설정에 플랫폼별 코드 서명을 추가하세요.

// package.json "build" 또는 electron-builder.json
"mac": { "identity": "Developer ID Application: Your Name (TEAMID)" },
"win": { "certificateSubjectName": "Your Company" }`;

export const EA061: AggregateRule = {
  id: 'EA061',
  kind: 'aggregate',
  severity: 'low',
  target: 'electron-builder 코드 서명 설정 부재',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const rootDir = context.project.rootDir;
    if (!rootDir) {
      return [];
    }

    const usesBuilder =
      (context.project.dependencyNames?.has('electron-builder') ?? false) ||
      context.project.packageJsonBuild !== undefined ||
      hasAnyConfigFile(rootDir);
    if (!usesBuilder) {
      return []; // electron-builder isn't used — nothing to flag.
    }

    const config = resolveInspectableConfig(rootDir, context.project.packageJsonBuild);
    if (config === undefined) {
      // electron-builder is used, but its config lives only in a file we
      // can't parse (YAML/JS/TOML) — we can't verify signing is absent, so
      // we stay silent rather than risk a false positive.
      return [];
    }

    if (hasSigningConfig(config)) {
      return [];
    }

    return [
      {
        ruleId: 'EA061',
        severity: 'low',
        // Absence-of-config judgment across manifest + config files — an
        // advisory hygiene signal, not certainty.
        confidence: 'heuristic',
        file: context.project.packageJsonPath ?? path.join(rootDir, 'package.json'),
        line: 0,
        target: 'electron-builder를 쓰지만 코드 서명(mac.identity / win.certificate*) 설정이 없음',
        whyDangerous: WHY_DANGEROUS,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};

function hasAnyConfigFile(rootDir: string): boolean {
  return [...PARSEABLE_CONFIG_FILES, ...UNPARSEABLE_CONFIG_FILES].some((name) =>
    existsSync(path.join(rootDir, name)),
  );
}

// Returns the electron-builder config object we can actually inspect, or
// undefined when the only config is in an unparseable file. A dedicated
// config file takes precedence over the package.json `build` field.
function resolveInspectableConfig(rootDir: string, packageJsonBuild: unknown): Record<string, unknown> | undefined {
  for (const name of PARSEABLE_CONFIG_FILES) {
    const configPath = path.join(rootDir, name);
    if (existsSync(configPath)) {
      try {
        return JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, unknown>;
      } catch {
        return undefined; // present but unparseable → can't verify
      }
    }
  }

  if (UNPARSEABLE_CONFIG_FILES.some((name) => existsSync(path.join(rootDir, name)))) {
    return undefined; // config lives in a format we don't parse
  }

  if (packageJsonBuild !== undefined && typeof packageJsonBuild === 'object' && packageJsonBuild !== null) {
    return packageJsonBuild as Record<string, unknown>;
  }

  return undefined;
}

// Any truthy signing indicator across mac/win config counts as "signing is
// set up". `mac.identity: null` (explicitly disabling signing) is NOT an
// indicator, so it still flags — an unsigned build is an unsigned build.
function hasSigningConfig(config: Record<string, unknown>): boolean {
  const mac = asObject(config.mac);
  const win = asObject(config.win);

  const macSigned = truthy(mac?.identity) || truthy(mac?.notarize) || truthy(config.afterSign);
  const winSigned =
    truthy(win?.certificateFile) ||
    truthy(win?.certificateSubjectName) ||
    truthy(win?.certificateSha1) ||
    truthy(win?.signtoolOptions) ||
    truthy(win?.sign) ||
    truthy(win?.signingHashAlgorithms);

  return macSigned || winSigned;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
}

function truthy(value: unknown): boolean {
  return value !== undefined && value !== null && value !== false && value !== '';
}
