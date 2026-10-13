module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended', 'prettier'],
  env: { node: true, jest: true, es2022: true },
  ignorePatterns: ['dist/', 'var/', 'node_modules/', 'coverage/'],
  rules: {
    'no-console': 'error',
    eqeqeq: 'error',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'max-lines-per-function': ['error', { max: 50, skipBlankLines: true, skipComments: true }],
  },
  overrides: [
    {
      files: ['**/*.spec.ts'],
      rules: { 'max-lines-per-function': 'off' },
    },
  ],
};
