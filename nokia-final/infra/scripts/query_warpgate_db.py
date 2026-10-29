import sqlite3
import sys
import os

db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ.get("TEMP", "/tmp"), "warpgate.sqlite3")

con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

print("=== TABLES ===")
for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
    print(name)

print()
print("=== USERS ===")
try:
    for row in con.execute("SELECT id, username, description FROM users"):
        print(row)
except Exception as e:
    print("users error:", e)

print()
print("=== TARGETS ===")
try:
    for row in con.execute("SELECT id, name, kind FROM targets"):
        print(row)
except Exception as e:
    print("targets error:", e)

print()
print("=== CREDENTIALS ===")
try:
    for row in con.execute("SELECT user_id, kind FROM credentials"):
        print(row)
except Exception as e:
    print("credentials error:", e)

con.close()
