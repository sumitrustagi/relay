"""add has_audit to platform_settings

Revision ID: 0003_add_has_audit
Revises: 0002_cucm_clusters
Create Date: 2026-03-18 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision      = '0003_add_has_audit'
down_revision = '0002_cucm_clusters'
branch_labels = None
depends_on    = None


def upgrade():
    with op.batch_alter_table('platform_settings') as batch_op:
        batch_op.add_column(
            sa.Column('has_audit', sa.Boolean(), nullable=True, server_default='0')
        )
    # Also fix ldap_servers table to match the current model
    # (migration 0001 had wrong column names if DB was created via db.create_all)
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    ldap_cols = [c['name'] for c in inspector.get_columns('ldap_servers')]

    with op.batch_alter_table('ldap_servers') as batch_op:
        if 'name' not in ldap_cols:
            batch_op.add_column(sa.Column('name', sa.String(100), nullable=True))
        if 'attr_name' not in ldap_cols:
            batch_op.add_column(sa.Column('attr_name', sa.String(80), nullable=True))
        if 'attr_email' not in ldap_cols:
            batch_op.add_column(sa.Column('attr_email', sa.String(80), nullable=True))
        if 'attr_uid' not in ldap_cols:
            batch_op.add_column(sa.Column('attr_uid', sa.String(80), nullable=True))
        if 'attr_phone' not in ldap_cols:
            batch_op.add_column(sa.Column('attr_phone', sa.String(80), nullable=True))
        if 'use_ssl' not in ldap_cols:
            batch_op.add_column(sa.Column('use_ssl', sa.Boolean(), nullable=True))
        if 'use_tls' not in ldap_cols:
            batch_op.add_column(sa.Column('use_tls', sa.Boolean(), nullable=True))
        if 'is_active' not in ldap_cols:
            batch_op.add_column(sa.Column('is_active', sa.Boolean(), nullable=True))
        if 'last_sync_at' not in ldap_cols:
            batch_op.add_column(sa.Column('last_sync_at', sa.DateTime(), nullable=True))
        if 'last_sync_ok' not in ldap_cols:
            batch_op.add_column(sa.Column('last_sync_ok', sa.Boolean(), nullable=True))
        if 'last_sync_msg' not in ldap_cols:
            batch_op.add_column(sa.Column('last_sync_msg', sa.String(300), nullable=True))
        if 'last_sync_count' not in ldap_cols:
            batch_op.add_column(sa.Column('last_sync_count', sa.Integer(), nullable=True))
        if 'added_by' not in ldap_cols:
            batch_op.add_column(sa.Column('added_by', sa.String(80), nullable=True))


def downgrade():
    with op.batch_alter_table('platform_settings') as batch_op:
        batch_op.drop_column('has_audit')
