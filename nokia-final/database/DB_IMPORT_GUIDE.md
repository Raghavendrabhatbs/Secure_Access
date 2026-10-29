# Nokia SSH Session Database — Import Guide

The dumps in this folder contain the recorded SSH sessions used by the chatbot:

| File | Contents |
|---|---|
| `nokia_sessions_backup.sql` | Schema **and** data (full restore) |
| `nokia_sessions_data_only.sql` | Data only (use when the schema already exists) |

The dump contains 87 physical `sessions` rows representing 80 distinct
`session_id` values; seven IDs have both plain and composite-key rows. It also
contains 100 commands, 169 events, plus saved chatbot conversations. Both
files use `INSERT` statements and carry no owner or privilege settings, so
they import under any role name.

> This is real session data. Keep the repository **private**.

## Prerequisites

- Docker Desktop running.
- A PostgreSQL container named `nokia-postgres` with a role `nokia`
  (see "Create the container" below if you do not have one).
- Stop the API before importing, because it holds connections to the database.

## Full import (schema + data)

Run from the project root in PowerShell. This **replaces** any existing
`nokia_ssh` database.

```powershell
git pull

docker start nokia-postgres

# copy the dump into the container (works in PowerShell and cmd)
docker cp database/nokia_sessions_backup.sql nokia-postgres:/tmp/import.sql

# recreate the database and load the dump
docker exec nokia-postgres psql -U nokia -d postgres -c "DROP DATABASE IF EXISTS nokia_ssh"
docker exec nokia-postgres psql -U nokia -d postgres -c "CREATE DATABASE nokia_ssh"
docker exec nokia-postgres psql -U nokia -d nokia_ssh -v ON_ERROR_STOP=1 -f /tmp/import.sql

docker exec nokia-postgres rm /tmp/import.sql
```

Do not use `psql < file.sql` in PowerShell; the `<` redirect is not supported
there.

## Verify

```powershell
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "SELECT COUNT(*) FROM sessions;"          # 87
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "SELECT COUNT(*) FROM session_commands;"  # 100
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "\dt"
```

The dump includes the `alembic_version` table, so `alembic upgrade head` will
not try to re-create anything.

## Data-only import

Use this if the tables already exist (for example after
`alembic upgrade head` on an empty database). Existing rows are **not**
removed, so import into empty tables or you will get duplicate-key errors.

```powershell
docker cp database/nokia_sessions_data_only.sql nokia-postgres:/tmp/import.sql
docker exec nokia-postgres psql -U nokia -d nokia_ssh -v ON_ERROR_STOP=1 -f /tmp/import.sql
docker exec nokia-postgres rm /tmp/import.sql
```

## Point the app at the database

In `services/api/.env` set:

```dotenv
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=nokia_ssh
POSTGRES_USER=nokia
POSTGRES_PASSWORD=<your database password>
```

Then start Ollama and the chatbot (see `SETUP_GUIDE.md`, Part 2) and try:

- "What were the most dangerous commands used?"
- "Show me all sessions from the last 7 days"
- "Were there any rm -rf commands executed?"
- "Which users had the most sessions?"
- "Show me sessions where malicious activity was detected"
- "How many total sessions are recorded?"

## Create the container (if you do not have one)

The root `docker-compose.yml` is empty, so there is no compose file to run.
Start PostgreSQL yourself, choosing your own password:

```powershell
docker run -d --name nokia-postgres -p 5432:5432 `
  -e POSTGRES_USER=nokia -e POSTGRES_PASSWORD=<choose-a-password> `
  -e POSTGRES_DB=nokia_ssh postgres:16
```

Use the same password in `services/api/.env`.

## Troubleshooting

| Message | Fix |
|---|---|
| `No such container: nokia-postgres` | Create it as shown above, or `docker start nokia-postgres` if it exists |
| `role "nokia" does not exist` | The container was created with a different user. Recreate it with `POSTGRES_USER=nokia`, or replace `nokia` in the commands with your superuser |
| `database "nokia" does not exist` | Add `-d postgres` (or `-d nokia_ssh`) to the `psql` command |
| `database "nokia_ssh" is being accessed by other users` | Stop the API and any `psql` sessions, then retry the DROP |
| Chatbot answers are empty | Check the counts in "Verify", and that `POSTGRES_DB=nokia_ssh` in `services/api/.env` |
