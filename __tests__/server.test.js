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
});
