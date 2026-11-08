"""One-shot volume/secret ownership preparation. Long-running services are non-root."""
import os,shutil
from pathlib import Path
for name,target in [('master_key','/master/master_key'),('research_token','/research/research_token'),('verify_token','/verify/verify_token'),('app_postgres_password','/dbkey/postgres_password'),('redis_password','/dbkey/redis_password')]:
 p=Path(target);p.parent.mkdir(exist_ok=True)
 os.chown(p.parent,10001,10001);p.parent.chmod(0o700)
 shutil.copyfile('/run/secrets/'+name,p);os.chown(p,10001,10001);p.chmod(0o400)
os.chown('/data',10001,10001);os.chmod('/data',0o700)
os.setgid(10001);os.setuid(10001)
from alembic import command
from alembic.config import Config
command.upgrade(Config('alembic.ini'),'head')
from .db import engine
from psycopg import sql
with engine().connect() as conn:
 raw=conn.connection.driver_connection
 with raw.cursor() as cursor:
  cursor.execute("SELECT 1 FROM pg_roles WHERE rolname='atlas_app'")
  if not cursor.fetchone():cursor.execute(sql.SQL('CREATE ROLE atlas_app LOGIN PASSWORD {}').format(sql.Literal(Path('/dbkey/postgres_password').read_text().strip())))
  cursor.execute('GRANT CONNECT ON DATABASE atlas TO atlas_app')
  cursor.execute('GRANT USAGE ON SCHEMA public TO atlas_app')
  cursor.execute('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO atlas_app')
  cursor.execute('REVOKE UPDATE,DELETE ON journal FROM atlas_app')
 raw.commit()
