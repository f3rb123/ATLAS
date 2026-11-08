from alembic import context
from atlas.db import Base, engine
with engine().connect() as conn:
    context.configure(connection=conn,target_metadata=Base.metadata)
    with context.begin_transaction():context.run_migrations()
