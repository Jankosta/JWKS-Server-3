// Jacob Pavlick - jmp0586

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const port = 8080;

const DB_FILE = path.join(process.cwd(), 'totally_not_my_privateKeys.db');

// ensure DB file exists
let db;
let ready = false;
let readyPromise;

/* eslint-disable-next-line no-bitwise */
const OPEN_FLAGS = sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE;

function openDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_FILE, OPEN_FLAGS, (err) => {
      if (err) {
        return reject(err);
      }
      // create table if not exists
      db.run(
        `CREATE TABLE IF NOT EXISTS keys(
          kid INTEGER PRIMARY KEY AUTOINCREMENT,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL
        )`,
        (runErr) => {
          if (runErr) {
            return reject(runErr);
          }
          return resolve();
        },
      );
    });
  });
}

// save private key PEM and expiry using parameterized query
function saveKey(pem, exp) {
  return new Promise((resolve, reject) => {
    const sql = 'INSERT INTO keys(key, exp) VALUES(?, ?)';
    db.run(sql, [pem, exp], function (err) {
      if (err) return reject(err);
      resolve(this.lastID);
    });
  });
}

// read keys: expiredFlag=true -> expired keys, else non-expired
function getKeys(expiredFlag) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    let sql;
    let params;
    if (expiredFlag) {
      sql = 'SELECT kid, key, exp FROM keys WHERE exp <= ?';
      params = [now];
    } else {
      sql = 'SELECT kid, key, exp FROM keys WHERE exp > ?';
      params = [now];
    }
    db.all(sql, params, (err, rows) => {
      if (err) {
        return reject(err);
      }
      return resolve(rows);
    });
  });
}

// read all non-expired keys for JWKS
function getValidKeys() {
  return getKeys(false);
}

// read one key (expired or not)
function getOneKey(expiredFlag) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    let sql;
    let params;
    if (expiredFlag) {
      sql = 'SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1';
      params = [now];
    } else {
      sql = 'SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1';
      params = [now];
    }
    db.get(sql, params, (err, row) => {
      if (err) {
        return reject(err);
      }
      return resolve(row);
    });
  });
}

// helper to use db.get with promises
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        return reject(err);
      }
      return resolve(row);
    });
  });
}

// delay handling until DB/keys are ready
app.use((req, res, next) => {
  if (ready) return next();
  if (!readyPromise) return next();
  readyPromise.then(() => next()).catch(next);
});

// enforce POST on /auth
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  return next();
});

// ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  return next();
});

// GET JWKS: read all valid (non-expired) keys and return their public JWKs
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const rows = await getValidKeys();
    // rows[].key contains PEM private key; convert to node-jose Key objects to extract public JWK
    const jwks = await Promise.all(rows.map(async (row) => {
      const key = await jose.JWK.asKey(row.key, 'pem');
      // ensure the public JWK uses the DB `kid` so tokens signed with that kid are verifiable
      try {
        key.kid = row.kid.toString();
      } catch (e) {
        // ignore
      }
      const publicJwk = key.toJSON();
      publicJwk.kid = row.kid.toString();
      return publicJwk;
    }));
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: jwks });
  } catch (err) {
    console.error('Error building JWKS:', err);
    res.status(500).send('Internal Server Error');
  }
});

// POST /auth: return a JWT signed with either an expired or valid private key from DB
app.post('/auth', async (req, res) => {
  try {
    const wantsExpired = req.query.expired === 'true';
    const row = await getOneKey(wantsExpired);
    if (!row) {
      return res.status(500).send('No matching key in DB');
    }
    // row.key is PEM private key
    const privatePem = row.key;
    const kid = row.kid.toString();
    const now = Math.floor(Date.now() / 1000);
    // JWT payloads include username from a fake auth
    let payload;
    if (wantsExpired) {
      // make the token expired: issued in the past and expired in the past
      payload = {
        user: 'userABC',
        iat: now - 3600,
        exp: now - 10,
      };
    } else {
      payload = {
        user: 'userABC',
        iat: now,
        exp: now + 3600,
      };
    }
    const options = {
      algorithm: 'RS256',
      header: {
        typ: 'JWT',
        alg: 'RS256',
        kid,
      },
    };
    const signed = jwt.sign(payload, privatePem, options);
    res.send(signed);
  } catch (err) {
    console.error('Error signing JWT:', err);
    res.status(500).send('Internal Server Error');
  }
});

// generate keys and persist to DB ensuring at least one expired and one valid key
async function ensureKeysInDb() {
  const now = Math.floor(Date.now() / 1000);
  // count valid and expired keys
  const validRow = await dbGet('SELECT COUNT(*) AS validCnt FROM keys WHERE exp > ?', [now]);
  const expiredRow = await dbGet('SELECT COUNT(*) AS expiredCnt FROM keys WHERE exp <= ?', [now]);

  const validCnt = validRow ? validRow.validCnt : 0;
  const expiredCnt = expiredRow ? expiredRow.expiredCnt : 0;

  if (validCnt === 0) {
    const validKey = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    const validPem = validKey.toPEM(true);
    const validExp = now + 3600;
    // eslint-disable-next-line no-await-in-loop
    await saveKey(validPem, validExp);
  }

  if (expiredCnt === 0) {
    const expiredKey = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    const expiredPem = expiredKey.toPEM(true);
    const expiredExp = now - 10; // already expired
    await saveKey(expiredPem, expiredExp);
  }
}

// open DB ensure keys exist then listen when run directly
readyPromise = openDatabase()
  .then(() => ensureKeysInDb())
  .then(() => {
    ready = true;
    if (require.main === module) {
      app.listen(port, () => {
        console.log(`Server started on http://localhost:${port}`);
      });
    }
  })
  .catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });

// export for tests
module.exports = app;

// expose internal helpers for unit tests
module.exports._test = {
  saveKey,
  getKeys,
  getOneKey,
  dbGet,
  ensureKeysInDb,
  openDatabase,
};

// expose DB for tests
module.exports._getDb = function getDb() {
  return db;
};
