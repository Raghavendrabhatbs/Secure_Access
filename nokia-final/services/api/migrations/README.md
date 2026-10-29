# Database Migrations

## `blocked_users` table

The SSH proxy's persistent user block and unblock endpoints require this
table. Apply it with the existing Alembic configuration; no SQL dump or manual
table creation is needed.

Migration: `alembic/versions/9d2a7f4c1e30_add_blocked_users.py`

Parent revision: `7c1d4b2e8a10`.

Before applying, ensure PostgreSQL is running and `services/api/.env` contains
the database connection settings. Alembic loads these settings from the same
file used by the API. Back up the database according to your normal operations
procedure. Do not paste credentials into commands or commit `.env` files.

From the project root in PowerShell:

```powershell
Set-Location C:\SecureAccess\nokia-final\services\api
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m alembic current
```

The migration adds only `blocked_users` and its indexes. It does not drop or
recreate existing session or command data.

Verify the migration:

```powershell
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "\d blocked_users"
docker exec nokia-postgres psql -U nokia -d nokia_ssh -c "SELECT version_num FROM alembic_version;"
```

If the table already exists but Alembic does not show this revision, stop and
have the database maintainer compare the schema and migration history. Do not
drop the table or stamp the migration blindly.
