# JWKS Server (Project 3)

This repository implements Project 3: an enhanced SQLite-backed JWKS (JSON Web Key Set) server with AES encryption, user management, authentication logging, and rate limiting. The server persists encrypted private keys in a local database and exposes:

- GET /.well-known/jwks.json — public JWKs for all non-expired keys in the database
- POST /auth[?expired=true] — issues a JWT signed with a private key from the database; when `expired=true` the server returns a JWT whose exp/iat are in the past (useful for testing). All successful authentication requests are logged.
- POST /register — creates a new user with a UUIDv4 password, hashes it with Argon2, and returns the password

The server stores AES-encrypted PEM-serialized private keys in a SQLite database file named `totally_not_my_privateKeys.db` and ensures on startup that at least one expired and one valid key exist. Private keys are encrypted using AES-256-CBC with a key from the `NOT_MY_KEY` environment variable.

## Database schema

The database file is created in the repository root. Table schemas:

```sql
CREATE TABLE IF NOT EXISTS keys(
  kid INTEGER PRIMARY KEY AUTOINCREMENT,
  key BLOB NOT NULL,
  exp INTEGER NOT NULL
)

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email TEXT UNIQUE,
  date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
)

CREATE TABLE IF NOT EXISTS auth_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_ip TEXT NOT NULL,
  request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
)
```

## How to run

1. Install Node.js

2. Clone the repository and install dependencies:

```powershell
git clone <repo-url>
cd JWKS-Server-3
npm install
```

3. Set the encryption key environment variable and start the server locally. For ease of testing, use the following command:

```powershell
$env:NOT_MY_KEY='mysecretencryptionkey123456789012'; npm start
```

4. Run gradebot.exe:

```powershell
./gradebot project3
```

## Features

### AES Encryption

- Private keys are encrypted using AES-256-CBC before being stored in the database
- Encryption key is sourced from the `NOT_MY_KEY` environment variable
- Each encryption uses a random initialization vector (IV) for security
- Keys are decrypted automatically when retrieved from the database

### User Registration

- POST /register endpoint accepts `username` and `email` in the request body
- Generates a secure UUIDv4 password for each user
- Hashes passwords using Argon2id with configurable parameters
- Returns the generated password in the response (HTTP 201)

### Authentication Logging

- All successful POST /auth requests are logged to the `auth_logs` table
- Logs include request IP address, timestamp, and user ID (if applicable)
- Failed or rate-limited requests are not logged

### Rate Limiting

- POST /auth endpoint is rate-limited to 10 requests per second per IP address
- Requests exceeding the limit receive HTTP 429 (Too Many Requests)
- Uses in-memory rate limiting for optimal performance

## Tests

This repository includes unit and integration tests using Jest and Supertest. To run tests and collect coverage:

```powershell
$env:NOT_MY_KEY='mysecretencryptionkey123456789012'; npm test
```

## Linting

ESLint is configured with the Airbnb base config. Run the linter with:

```powershell
npm run lint
```

Automatically fix fixable issues:

```powershell
npm run lint:fix
```

## Files of interest

- `server.js` — main Express app, DB helpers, routes, and exported internal helpers used by tests
- `package.json` — scripts for test, start, lint; dependency listings
- `totally_not_my_privateKeys.db` — generated at runtime when the server is started
- `__tests__/` — Jest test suites covering endpoints and internal helpers

## Grading notes

- Author: Jacob Pavlick - jmp0586 (jacobpavlick@my.unt.edu)

- All necessary screenshots are available in Screenshots/

## Language / Platform

- Language: JavaScript (Node.js)
- Recommended Node.js version: 18.x or later (the project was developed and tested using Node.js 18+).

- OS / Platform: Developed and tested on Windows (PowerShell).

## AI Acknowledgment

Assistance was received from **GitHub Copilot** with the **Claude Sonnet 4.5** model to aid in development of this project. The AI was used for implementing all requirements listed in project 3. The entire project description was provided in the prompt, as well as reference to the base files from project 2, and the AI worked from there. The AI model also generated tests based on this prompt. Additionally, the AI was prompted to update the README according to the changes that were made.
