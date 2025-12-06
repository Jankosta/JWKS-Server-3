// Jacob Pavlick - jmp0586

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const argon2 = require('argon2');
/* eslint-disable-next-line import/no-unresolved */
const { v4: uuidv4 } = require('uuid');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const app = express();
const port = 8080;

const DB_FILE = path.join(process.cwd(), 'totally_not_my_privateKeys.db');

// AES encryption key from environment variable
const AES_KEY = process.env.NOT_MY_KEY || 'default_insecure_key_do_not_use_in_production';
const ALGORITHM = 'aes-256-cbc';

// Ensure key is correct length
const ENCRYPTION_KEY = crypto.createHash('sha256').update(AES_KEY).digest();

// Rate limiter for /auth endpoint (10 requests per second)
const rateLimiter = new RateLimiterMemory({
  points: 10, // 10 requests
  duration: 1, // per 1 second
});

// Middleware to parse JSON bodies
app.use(express.json());

// ensure DB file exists
let db;
let ready = false;
let readyPromise;

/* eslint-disable-next-line no-bitwise */
const OPEN_FLAGS = sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE;

// AES Encryption functions
function encryptKey(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  // Return IV + encrypted data (IV is not secret)
  return `${iv.toString('hex')}:${encrypted}`;
}

function decryptKey(ciphertext) {
  const parts = ciphertext.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_FILE, OPEN_FLAGS, (err) => {
      if (err) {
        return reject(err);
      }
      // create keys table if not exists
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
          // create users table
          db.run(
            `CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              email TEXT UNIQUE,
              date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              last_login TIMESTAMP      
            )`,
            (usersErr) => {
              if (usersErr) {
                return reject(usersErr);
              }
              // create auth_logs table
              db.run(
                `CREATE TABLE IF NOT EXISTS auth_logs(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  request_ip TEXT NOT NULL,
                  request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  user_id INTEGER,  
                  FOREIGN KEY(user_id) REFERENCES users(id)
                )`,
                (logsErr) => {
                  if (logsErr) {
                    return reject(logsErr);
                  }
                  return resolve();
                },
              );
            },
          );
        },
      );
    });
  });
}

// save private key PEM and expiry using parameterized query (with encryption)
function saveKey(pem, exp) {
  return new Promise((resolve, reject) => {
    const encryptedKey = encryptKey(pem);
    const sql = 'INSERT INTO keys(key, exp) VALUES(?, ?)';
    db.run(sql, [encryptedKey, exp], function (err) {
      if (err) return reject(err);
      resolve(this.lastID);
    });
  });
}

// read keys: expiredFlag=true -> expired keys, else non-expired (with decryption)
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
      // Decrypt keys
      const decryptedRows = rows.map((row) => ({
        ...row,
        key: decryptKey(row.key),
      }));
      return resolve(decryptedRows);
    });
  });
}

// read all non-expired keys for JWKS
function getValidKeys() {
  return getKeys(false);
}

// read one key (expired or not) with decryption
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
      if (row) {
        const decryptedRow = { ...row, key: decryptKey(row.key) };
        return resolve(decryptedRow);
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

// ensure only POST requests are allowed for /register
app.all('/register', (req, res, next) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  return next();
});

// POST /register: create new user with generated password
app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;

    if (!username || !email) {
      return res.status(400).json({ error: 'Username and email are required' });
    }

    // Generate secure password using UUIDv4
    const password = uuidv4();

    // Hash password with Argon2
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: 3,
      parallelism: 4,
    });

    // Insert user into database
    const sql = 'INSERT INTO users(username, password_hash, email) VALUES(?, ?, ?)';

    await new Promise((resolve, reject) => {
      db.run(sql, [username, passwordHash, email], function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return reject(new Error('Username or email already exists'));
          }
          return reject(err);
        }
        resolve(this.lastID);
      });
    });

    // Return password to user
    res.status(201).json({ password });
  } catch (err) {
    console.error('Error registering user:', err);
    if (err.message.includes('already exists')) {
      return res.status(409).json({ error: err.message });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
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
    // Get client IP first for both rate limiting and logging
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

    // Rate limiting
    try {
      await rateLimiter.consume(clientIp);
    } catch (rateLimitErr) {
      // Don't log rate-limited requests
      return res.status(429).json({ error: 'Too Many Requests' });
    }

    const wantsExpired = req.query.expired === 'true';
    const row = await getOneKey(wantsExpired);
    if (!row) {
      return res.status(500).send('No matching key in DB');
    }

    // row.key is PEM private key
    const privatePem = row.key;
    const kid = row.kid.toString();
    const now = Math.floor(Date.now() / 1000);

    // Get username from request body (default to 'userABC' for backwards compatibility)
    const username = req.body && req.body.username ? req.body.username : 'userABC';

    // Look up user_id from username
    let userId = null;
    const userRow = await dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (userRow) {
      userId = userRow.id;
    }

    // JWT payloads include username from auth request
    let payload;
    if (wantsExpired) {
      // make the token expired: issued in the past and expired in the past
      payload = {
        user: username,
        iat: now - 3600,
        exp: now - 10,
      };
    } else {
      payload = {
        user: username,
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

    // Log authentication request (always log successful auth requests)
    const logSql = 'INSERT INTO auth_logs(request_ip, user_id) VALUES(?, ?)';
    db.run(logSql, [clientIp, userId], (err) => {
      if (err) {
        console.error('Error logging auth request:', err);
        // Don't fail the request if logging fails
      }
    });

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
  encryptKey,
  decryptKey,
};

// expose DB for tests
module.exports._getDb = function getDb() {
  return db;
};
