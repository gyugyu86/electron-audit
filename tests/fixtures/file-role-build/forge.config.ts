// Build tooling recognized by filename at the project root — a packaging
// config, with no application source directory above it.
import { execSync } from 'node:child_process';

export default {
  hooks: {
    postPackage: (_config: unknown, outDir: string): void => {
      // EA020
      execSync(`codesign --force ${outDir}`);
    },
  },
};
