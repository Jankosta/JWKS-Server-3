# JWKS Server (Project 2)

This repository implements Project 2: a SQLite-backed JWKS (JSON Web Key Set) server that persists private keys in a local database and exposes:

- GET /.well-known/jwks.json — public JWKs for all non-expired keys in the database
- POST /auth[?expired=true] — issues a JWT signed with a private key from the database; when `expired=true` the server returns a JWT whose exp/iat are in the past (useful for testing)

The server stores PEM-serialized private keys in a SQLite database file named `totally_not_my_privateKeys.db` and ensures on startup that at least one expired and one valid key exist.

## Database schema

The database file is created in the repository root. Table schema:

CREATE TABLE IF NOT EXISTS keys(
kid INTEGER PRIMARY KEY AUTOINCREMENT,
key BLOB NOT NULL,
exp INTEGER NOT NULL
)

## How to run

1. Install Node.js

2. Clone the repository and install dependencies:

```powershell
git clone <repo-url>
cd JWKS-Server-2
npm install
```

3. Start the server locally:

```powershell
npm start
```

4. Run gradebot.exe:

```powershell
./gradebot project2
```

## Tests

This repository includes unit and integration tests using Jest and Supertest. To run tests and collect coverage:

```powershell
npm test
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

Assistance was received from **Copilot** with the **GPT-5 Mini** model to aid in development of this project, particularly in setting up project requirements, testing and linting. **Copilot** was used for error handling, offering suggestions and fixes whenever I could not locate the origin or solution to an issue. My mindset was first to see if I could solve the issue on my own, before then moving to ask AI for the root cause of the error and an explanation of how to fix it and how to avoid such issues in the future. Assistance was received from **Copilot** in regards to README formatting and review. **Copilot** was also utilized to suggest approaches for the project, suggesting what contents and changes should be done in each file to guide my decision making. It was additionally used in the initial setup phase in regards to installing the necessary packages. The prompts involved providing the AI with the assignment description as well as my personal goals for the project, asking it to suggest a clean and effective approach based off the existing Project 1 files. An example of such a prompt is as follows: "I have an assignment to build upon a simple JWKS server using Node.js and Express. Can you suggest a clean approach, including which files I should create/modify and what each should contain? Here is the project description: (Simplified Project 2 Description)"
