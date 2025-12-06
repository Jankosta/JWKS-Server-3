const jose = require('node-jose');
const request = require('supertest');
const sqlite3 = require('sqlite3');
const app = require('../server');

// increase timeout for key generation and DB ops
jest.setTimeout(20000);

const { _test: helpers } = app;

describe('DB helper functions', () => {
  beforeAll(async () => {
    // ensure DB is open and seeded
    await helpers.openDatabase();
    await helpers.ensureKeysInDb();
  });

  test('saveKey and getKeys work for valid and expired', async () => {
    const now = Math.floor(Date.now() / 1000);
    // generate a temporary key
    const key = await jose.JWK.createKey('RSA', 512, { alg: 'RS256', use: 'sig' });
    const pem = key.toPEM(true);

    // save a key (expired)
    const expiredExp = now - 20;
    const id1 = await helpers.saveKey(pem, expiredExp);
    expect(typeof id1).toBe('number');

    // save a future key
    const futureExp = now + 600;
    const id2 = await helpers.saveKey(pem, futureExp);
    expect(typeof id2).toBe('number');

    // get expired keys
    const expired = await helpers.getKeys(true);
    expect(Array.isArray(expired)).toBe(true);
    expect(expired.find((r) => r.kid === id1)).toBeDefined();

    // get valid keys
    const valid = await helpers.getKeys(false);
    expect(Array.isArray(valid)).toBe(true);
    expect(valid.find((r) => r.kid === id2)).toBeDefined();
  });

  test('getOneKey returns at least one row for expired and valid', async () => {
    const oneValid = await helpers.getOneKey(false);
    expect(oneValid).toBeDefined();
    const oneExpired = await helpers.getOneKey(true);
    expect(oneExpired).toBeDefined();
  });

  test('dbGet can retrieve count', async () => {
    const now = Math.floor(Date.now() / 1000);
    const row = await helpers.dbGet('SELECT COUNT(*) AS cnt FROM keys WHERE exp > ?', [now]);
    expect(row).toBeDefined();
    expect(typeof row.cnt === 'number' || typeof row.cnt === 'bigint').toBeTruthy();
  });

  test('dbGet rejects on invalid SQL', async () => {
    await expect(helpers.dbGet('SELECT * FROM definitely_not_a_table')).rejects.toBeTruthy();
  });

  test('JWKS endpoint returns 500 when jose.asKey throws', async () => {
    const original = jose.JWK.asKey;
    const origConsoleErr = console.error;
    console.error = jest.fn();
    jose.JWK.asKey = async () => { throw new Error('boom'); };
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(500);
    // restore
    jose.JWK.asKey = original;
    console.error = origConsoleErr;
  });

  test('POST /auth returns 500 when no keys present', async () => {
    // delete all keys from DB to simulate missing keys
    const db = app._getDb();
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM keys', (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
    const res = await request(app).post('/auth');
    expect(res.status).toBe(500);
    // repopulate
    await helpers.ensureKeysInDb();
  });

  test('openDatabase rejects when sqlite3.Database constructor fails', async () => {
    const orig = sqlite3.Database;
    sqlite3.Database = function stubDb(file, flags, cb) {
      cb(new Error('ctorfail'));
      return {};
    };
    await expect(helpers.openDatabase()).rejects.toBeTruthy();
    sqlite3.Database = orig;
  });

  test('openDatabase rejects when db.run returns an error', async () => {
    const orig = sqlite3.Database;
    sqlite3.Database = function stubDb2(file, flags, cb) {
      // call callback with no error and return object with run that calls callback with error
      const obj = {
        run(sql, callback) {
          callback(new Error('runerr'));
        },
      };
      cb(null);
      return obj;
    };
    await expect(helpers.openDatabase()).rejects.toBeTruthy();
    sqlite3.Database = orig;
  });
});
