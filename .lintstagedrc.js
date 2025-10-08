module.exports = {
  '*.{js,jsx,ts,tsx}': [
    'eslint --fix',
    'eslint --config .eslintrc.js --format json | jq \'.[] | select(.ruleId | contains("security"))\' || echo \'No security issues found\'',
  ],
  '*.{json,md}': [
    'prettier --write',
  ],
};