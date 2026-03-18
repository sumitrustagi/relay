"""add cucm_clusters table for multi-cluster support

Revision ID: 0002_cucm_clusters
Revises: 0001_initial
Create Date: 2026-03-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision      = '0002_cucm_clusters'
down_revision = '0001_initial'
branch_labels = None
depends_on    = None


def upgrade():
    op.create_table('cucm_clusters',
        sa.Column('id',            sa.Integer(),   nullable=False),
        sa.Column('label',         sa.String(120), nullable=False),
        sa.Column('cucm_host',     sa.String(255), nullable=True),
        sa.Column('cucm_username', sa.String(255), nullable=True),
        sa.Column('cucm_password', sa.String(255), nullable=True),
        sa.Column('cucm_version',  sa.String(10),  nullable=True),
        sa.Column('verify_ssl',    sa.Boolean(),   nullable=True),
        sa.Column('is_enabled',    sa.Boolean(),   nullable=True),
        sa.Column('created_at',    sa.DateTime(),  nullable=True),
        sa.Column('updated_at',    sa.DateTime(),  nullable=True),
        sa.Column('created_by',    sa.String(80),  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # If an existing single-cluster cucm_config row has data,
    # migrate it automatically into the new cucm_clusters table.
    bind = op.get_bind()
    result = bind.execute(sa.text(
        "SELECT cucm_host, cucm_username, cucm_password, cucm_version, verify_ssl "
        "FROM cucm_config LIMIT 1"
    ))
    row = result.fetchone()
    if row and row[0]:   # cucm_host is set
        bind.execute(sa.text(
            "INSERT INTO cucm_clusters "
            "(label, cucm_host, cucm_username, cucm_password, cucm_version, verify_ssl, is_enabled) "
            "VALUES ('Default', :host, :user, :pwd, :ver, :ssl, 1)"
        ), {
            "host": row[0],
            "user": row[1] or "",
            "pwd":  row[2] or "",
            "ver":  row[3] or "12.5",
            "ssl":  1 if row[4] else 0,
        })


def downgrade():
    op.drop_table('cucm_clusters')
