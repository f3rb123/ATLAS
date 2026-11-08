"""Enforce append-only journals inside the database, not only the ORM."""

from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
        op.execute(
            "ALTER TABLE knowledge_chunks ADD COLUMN embedding_vector vector(128)"
        )
        op.execute(
            "CREATE FUNCTION atlas_immutable_journal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'journal is append-only'; END $$"
        )
        op.execute(
            "CREATE TRIGGER immutable_journal BEFORE UPDATE OR DELETE ON journal FOR EACH ROW EXECUTE FUNCTION atlas_immutable_journal()"
        )
    else:
        op.execute(
            "CREATE TRIGGER immutable_journal_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END"
        )
        op.execute(
            "CREATE TRIGGER immutable_journal_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END"
        )


def downgrade():
    raise RuntimeError("Append-only audit protection cannot be silently downgraded")
