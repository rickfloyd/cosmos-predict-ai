module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: [
    'eslint:recommended',
    '@react-native/eslint-config',
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
    '@typescript-eslint',
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

    // React Security Rules
    'react/no-danger': 'error',
    'react/no-danger-with-children': 'error',

    // TypeScript Security Rules
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-non-null-assertion': 'warn',
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',

    // React Native Specific Rules
    'react-native/no-unused-styles': 'warn',
    'react-native/split-platform-components': 'warn',
    'react-native/no-inline-styles': 'warn',
    'react-native/no-color-literals': 'warn',

    // General Code Quality
    'no-console': 'warn',
    'no-debugger': 'error',
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',

    // Import Security
    'no-restricted-imports': [
      'error',
      {
        paths: [
          {
            name: 'eval',
            message: 'eval() is dangerous and should not be used',
          },
          {
            name: 'child_process',
            message: 'child_process should not be used in React Native',
          },
          {
            name: 'fs',
            message: 'fs module should not be used in React Native',
          },
        ],
      },
    ],

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
  settings: {
    react: {
      version: 'detect',
    },
  },
  ignorePatterns: [
    'node_modules/',
    'android/',
    'ios/',
    'build/',
    'dist/',
    '*.config.js',
    '*.config.ts',
  ],
};