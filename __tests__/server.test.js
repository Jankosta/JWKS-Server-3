const request = require('supertest');

jest.setTimeout(20000);

const app = require('../server');

describe('JWKS Server integration tests', () => {
  test('GET /.well-known/jwks.json returns keys array with at least one key', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body).toBeDefined();
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys.length).toBeGreaterThanOrEqual(1);
    // each key should have 'kty' and 'kid'
    expect(res.body.keys[0].kty).toBeDefined();
    expect(res.body.keys[0].kid).toBeDefined();
  });

  test('POST /auth returns a valid JWT signed with a valid (non-expired) key', async () => {
    const res = await request(app).post('/auth');
    expect(res.status).toBe(200);
    expect(typeof res.text).toBe('string');
    // basic JWT structure
    expect(res.text.split('.').length).toBe(3);
  });

  test('POST /auth?expired=true returns a JWT signed with an expired key', async () => {
    const res = await request(app).post('/auth?expired=true');
    expect(res.status).toBe(200);
    expect(typeof res.text).toBe('string');
    expect(res.text.split('.').length).toBe(3);
  });

  test('POST /auth with wrong method returns 405', async () => {
    const res = await request(app).get('/auth');
    expect(res.status).toBe(405);
  });

  test('GET /.well-known/jwks.json with wrong method returns 405', async () => {
    const res = await request(app).post('/.well-known/jwks.json');
    expect(res.status).toBe(405);
  });

  // Test user registration
  test('POST /register creates a new user and returns a password', async () => {
    const uniqueUsername = `testuser_${Date.now()}`;
    const uniqueEmail = `test_${Date.now()}@example.com`;

    const res = await request(app)
      .post('/register')
      .send({
        username: uniqueUsername,
        email: uniqueEmail,
      })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(201);
    expect(res.body).toBeDefined();
    expect(res.body.password).toBeDefined();
    expect(typeof res.body.password).toBe('string');
    // UUIDv4 format check
    expect(res.body.password).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test('POST /register with missing fields returns 400', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'testuser' })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(400);
  });

  test('POST /register with duplicate username returns 409', async () => {
    const uniqueUsername = `dupuser_${Date.now()}`;
    const uniqueEmail1 = `dup1_${Date.now()}@example.com`;
    const uniqueEmail2 = `dup2_${Date.now()}@example.com`;

    // First registration should succeed
    await request(app)
      .post('/register')
      .send({
        username: uniqueUsername,
        email: uniqueEmail1,
      })
      .set('Content-Type', 'application/json');

    // Second registration with same username should fail
    const res = await request(app)
      .post('/register')
      .send({
        username: uniqueUsername,
        email: uniqueEmail2,
      })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(409);
  });

  test('POST /register with wrong method returns 405', async () => {
    const res = await request(app).get('/register');
    expect(res.status).toBe(405);
  });

  // Test authentication logging
  test('POST /auth logs authentication request to database', async () => {
    const uniqueUsername = `loguser_${Date.now()}`;
    const uniqueEmail = `log_${Date.now()}@example.com`;

    // Register a user first
    await request(app)
      .post('/register')
      .send({
        username: uniqueUsername,
        email: uniqueEmail,
      })
      .set('Content-Type', 'application/json');

    // Authenticate
    const res = await request(app)
      .post('/auth')
      .send({ username: uniqueUsername })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(200);

    // Verify log entry exists (check via database)
    const db = app._getDb();
    const logEntry = await new Promise((resolve) => {
      db.get(
        'SELECT * FROM auth_logs WHERE user_id = (SELECT id FROM users WHERE username = ?) ORDER BY id DESC LIMIT 1',
        [uniqueUsername],
        (err, row) => {
          resolve(row);
        },
      );
    });

    expect(logEntry).toBeDefined();
    expect(logEntry.request_ip).toBeDefined();
  });

  // Test rate limiting
  test('POST /auth rate limits requests after 10 per second', async () => {
    const requests = [];

    // Send 12 requests rapidly
    for (let i = 0; i < 12; i += 1) {
      requests.push(request(app).post('/auth'));
    }

    const responses = await Promise.all(requests);

    // Count how many got rate limited
    const rateLimited = responses.filter((r) => r.status === 429);

    // At least some should be rate limited
    expect(rateLimited.length).toBeGreaterThan(0);
  }, 10000);
});
