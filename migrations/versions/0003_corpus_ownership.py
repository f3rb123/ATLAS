"""Prevent private owner documents entering another researcher's context."""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"


def upgrade():
    # Initial schema is frozen at revision 0001 before this migration is published.
    columns = [c["name"] for c in sa.inspect(op.get_bind()).get_columns("knowledge")]
    if "owner" not in columns:
        op.add_column(
            "knowledge",
            sa.Column("owner", sa.String(36), nullable=False, server_default="public"),
        )
    op.create_index("ix_knowledge_owner", "knowledge", ["owner"], if_not_exists=True)


def downgrade():
    raise RuntimeError("Private corpus ownership cannot be silently removed")
