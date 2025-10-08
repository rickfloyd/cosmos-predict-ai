module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaFeatures: {
      jsx: true,
    },
    ecmaVersion: 12,
    sourceType: 'module',
  },
  plugins: [
    'security',
  ],
  rules: {
    // Security Rules
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'error',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-new-buffer': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-non-literal-require': 'error',
    'security/detect-object-injection': 'error',
    'security/detect-possible-timing-attacks': 'error',
    'security/detect-pseudoRandomBytes': 'error',
    'security/detect-unsafe-regex': 'error',

    // Custom Security Rules for AI Code
    'no-restricted-syntax': [
      'error',
      {
        selector: 'CallExpression[callee.name="eval"]',
        message: 'eval() is dangerous and can execute malicious code',
      },
      {
        selector: 'CallExpression[callee.name="Function"]',
        message: 'new Function() can execute arbitrary code',
      },
      {
        selector: 'CallExpression[callee.name="setTimeout"][arguments.0.type="Literal"]',
        message: 'setTimeout with string can execute code - use function instead',
      },
      {
        selector: 'CallExpression[callee.name="setInterval"][arguments.0.type="Literal"]',
        message: 'setInterval with string can execute code - use function instead',
      },
    ],
  },
};