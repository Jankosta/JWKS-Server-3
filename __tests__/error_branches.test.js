const app = require('../server');

const { _test: helpers, _getDb } = app;

describe('error branch tests', () => {
  test('getKeys rejects when db.all errors', async () => {
    const db = _getDb();
    const orig = db.all;
    db.all = (sql, params, cb) => cb(new Error('allErr'));
    await expect(helpers.getKeys(false)).rejects.toBeTruthy();
    db.all = orig;
  });

  test('getOneKey rejects when db.get errors', async () => {
    const db = _getDb();
    const orig = db.get;
    db.get = (sql, params, cb) => cb(new Error('getErr'));
    await expect(helpers.getOneKey(false)).rejects.toBeTruthy();
    db.get = orig;
  });

  test('saveKey rejects when db.run errors', async () => {
    const db = _getDb();
    const orig = db.run;
    db.run = (sql, params, cb) => cb(new Error('runErr'));
    await expect(helpers.saveKey('pem', 1)).rejects.toBeTruthy();
    db.run = orig;
  });
});
