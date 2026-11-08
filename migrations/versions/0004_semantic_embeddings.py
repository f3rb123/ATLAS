"""Versioned real semantic embeddings with an explicit lexical fallback."""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"


def upgrade():
    cols = [
        c["name"] for c in sa.inspect(op.get_bind()).get_columns("knowledge_chunks")
    ]
    if "embedding_model" not in cols:
        op.add_column(
            "knowledge_chunks",
            sa.Column(
                "embedding_model",
                sa.String(192),
                nullable=False,
                server_default="signed-token-hash-v1-128",
            ),
        )
    op.create_index(
        "ix_knowledge_chunks_embedding_model",
        "knowledge_chunks",
        ["embedding_model"],
        if_not_exists=True,
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "ALTER TABLE knowledge_chunks ALTER COLUMN embedding_vector TYPE vector USING embedding_vector::vector"
        )


def downgrade():
    raise RuntimeError("Semantic index rollback requires an explicit reindex plan")
