module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true,
  },
  extends: 'airbnb-base',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'no-underscore-dangle': 'off',
    'no-console': 'off',
    'linebreak-style': 'off',
    'consistent-return': 'off',
    'func-names': 'off',
    'max-len': 'off',
  },
};
