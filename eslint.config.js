import tsPlugin from '@typescript-eslint/eslint-plugin';

export default [
  // tests/fixtures/** and every tests/corpus/<name>/ subdirectory are
  // deliberately arbitrary (and sometimes deliberately broken/vulnerable)
  // target-project samples, not our own code — never lint them. The *.ts
  // test files living directly under tests/corpus/ (e.g.
  // corpusRegression.test.ts) are our own code and still get linted.
  { ignores: ['dist/**', 'node_modules/**', 'tests/fixtures/**', 'tests/corpus/*/**'] },
  ...tsPlugin.configs['flat/strict'],
  {
    files: ['**/*.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
];
