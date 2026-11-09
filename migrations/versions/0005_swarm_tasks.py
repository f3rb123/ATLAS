"""Add durable specialist tasks without touching historical knowledge tables."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade():
    op.create_table(
        "swarm_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "run_id", sa.String(36), sa.ForeignKey("documents.id"), nullable=False
        ),
        sa.Column("owner", sa.String(36), nullable=False),
        sa.Column("role", sa.String(60), nullable=False),
        sa.Column("worker_kind", sa.String(20), nullable=False),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("result", sa.Text, nullable=False),
        sa.Column("priority", sa.Float, nullable=False),
        sa.Column("available_at", sa.Float, nullable=False),
        sa.Column("lease_until", sa.Float, nullable=False),
        sa.Column("lease_token", sa.String(36), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
        sa.Column("updated_at", sa.Float, nullable=False),
        sa.UniqueConstraint("run_id", "dedupe_key"),
    )
    for column in ("run_id", "owner", "worker_kind", "status"):
        op.create_index("ix_swarm_tasks_" + column, "swarm_tasks", [column])


def downgrade():
    raise RuntimeError(
        "Preserve task history; explicit archival required before removal"
    )
