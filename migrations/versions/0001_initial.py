"""initial schema — all tables

Revision ID: 0001_initial
Revises: 
Create Date: 2026-03-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision     = '0001_initial'
down_revision = None
branch_labels = None
depends_on    = None


def upgrade():
    op.create_table('platform_settings',
        sa.Column('id',               sa.Integer(),     nullable=False),
        sa.Column('client_name',      sa.String(120),   nullable=True),
        sa.Column('has_teams',        sa.Boolean(),     nullable=True),
        sa.Column('has_webex',        sa.Boolean(),     nullable=True),
        sa.Column('has_cucm',         sa.Boolean(),     nullable=True),
        sa.Column('has_cert_monitor', sa.Boolean(),     nullable=True),
        sa.Column('has_did',          sa.Boolean(),     nullable=True),
        sa.Column('has_ldap',         sa.Boolean(),     nullable=True),
        sa.Column('has_audit',        sa.Boolean(),     nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('ldap_servers',
        sa.Column('id',               sa.Integer(),     nullable=False),
        sa.Column('name',             sa.String(100),   nullable=False),
        sa.Column('host',             sa.String(255),   nullable=False),
        sa.Column('port',             sa.Integer(),     nullable=True),
        sa.Column('bind_dn',          sa.String(300),   nullable=True),
        sa.Column('bind_password',    sa.String(255),   nullable=True),
        sa.Column('base_dn',          sa.String(300),   nullable=True),
        sa.Column('user_filter',      sa.String(200),   nullable=True),
        sa.Column('attr_name',        sa.String(80),    nullable=True),
        sa.Column('attr_email',       sa.String(80),    nullable=True),
        sa.Column('attr_uid',         sa.String(80),    nullable=True),
        sa.Column('attr_phone',       sa.String(80),    nullable=True),
        sa.Column('use_ssl',          sa.Boolean(),     nullable=True),
        sa.Column('use_tls',          sa.Boolean(),     nullable=True),
        sa.Column('is_active',        sa.Boolean(),     nullable=True),
        sa.Column('last_sync_at',     sa.DateTime(),    nullable=True),
        sa.Column('last_sync_ok',     sa.Boolean(),     nullable=True),
        sa.Column('last_sync_msg',    sa.String(300),   nullable=True),
        sa.Column('last_sync_count',  sa.Integer(),     nullable=True),
        sa.Column('added_by',         sa.String(80),    nullable=True),
        sa.Column('created_at',       sa.DateTime(),    nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    op.create_table('users',
        sa.Column('id',              sa.Integer(),     nullable=False),
        sa.Column('username',        sa.String(80),    nullable=False),
        sa.Column('email',           sa.String(120),   nullable=False),
        sa.Column('password',        sa.String(255),   nullable=False),
        sa.Column('role',            sa.String(20),    nullable=False),
        sa.Column('is_active',       sa.Boolean(),     nullable=True),
        sa.Column('display_name',    sa.String(120),   nullable=True),
        sa.Column('teams_upn',       sa.String(255),   nullable=True),
        sa.Column('teams_extension', sa.String(50),    nullable=True),
        sa.Column('webex_extension', sa.String(50),    nullable=True),
        sa.Column('cucm_extension',  sa.String(50),    nullable=True),
        sa.Column('user_platform',   sa.String(20),    nullable=True),
        sa.Column('relay_role',      sa.String(20),    nullable=True),
        sa.Column('ldap_dn',         sa.String(500),   nullable=True),
        sa.Column('ldap_server_id',  sa.Integer(),     nullable=True),
        sa.Column('created_at',      sa.DateTime(),    nullable=True),
        sa.ForeignKeyConstraint(['ldap_server_id'], ['ldap_servers.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )

    op.create_table('ms_graph_config',
        sa.Column('id',                       sa.Integer(),  nullable=False),
        sa.Column('tenant_id',                sa.String(255), nullable=True),
        sa.Column('client_id',                sa.String(255), nullable=True),
        sa.Column('client_secret',            sa.String(255), nullable=True),
        sa.Column('service_account_upn',      sa.String(255), nullable=True),
        sa.Column('service_account_password', sa.String(255), nullable=True),
        sa.Column('graph_access_token',       sa.Text(),     nullable=True),
        sa.Column('graph_token_expiry',       sa.DateTime(), nullable=True),
        sa.Column('teams_access_token',       sa.Text(),     nullable=True),
        sa.Column('teams_token_expiry',       sa.DateTime(), nullable=True),
        sa.Column('updated_at',               sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('webex_config',
        sa.Column('id',            sa.Integer(),  nullable=False),
        sa.Column('client_id',     sa.String(255), nullable=True),
        sa.Column('client_secret', sa.String(255), nullable=True),
        sa.Column('refresh_token', sa.Text(),     nullable=True),
        sa.Column('access_token',  sa.Text(),     nullable=True),
        sa.Column('token_expiry',  sa.DateTime(), nullable=True),
        sa.Column('org_id',        sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('cucm_config',
        sa.Column('id',            sa.Integer(),  nullable=False),
        sa.Column('cucm_host',     sa.String(255), nullable=True),
        sa.Column('cucm_username', sa.String(255), nullable=True),
        sa.Column('cucm_password', sa.String(255), nullable=True),
        sa.Column('cucm_version',  sa.String(10),  nullable=True),
        sa.Column('verify_ssl',    sa.Boolean(),  nullable=True),
        sa.Column('updated_at',    sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('smtp_config',
        sa.Column('id',        sa.Integer(),  nullable=False),
        sa.Column('host',      sa.String(255), nullable=True),
        sa.Column('port',      sa.Integer(),  nullable=True),
        sa.Column('username',  sa.String(255), nullable=True),
        sa.Column('password',  sa.String(255), nullable=True),
        sa.Column('use_tls',   sa.Boolean(),  nullable=True),
        sa.Column('use_ssl',   sa.Boolean(),  nullable=True),
        sa.Column('from_addr', sa.String(255), nullable=True),
        sa.Column('from_name', sa.String(100), nullable=True),
        sa.Column('alert_to',  sa.Text(),     nullable=True),
        sa.Column('enabled',   sa.Boolean(),  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('sites',
        sa.Column('id',          sa.Integer(),  nullable=False),
        sa.Column('name',        sa.String(100), nullable=False),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('country',     sa.String(50),  nullable=True),
        sa.Column('created_at',  sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    op.create_table('schedules',
        sa.Column('id',             sa.Integer(),  nullable=False),
        sa.Column('name',           sa.String(100), nullable=True),
        sa.Column('platform',       sa.String(20),  nullable=False),
        sa.Column('user_id',        sa.String(255), nullable=True),
        sa.Column('user_upn',       sa.String(255), nullable=True),
        sa.Column('display_name',   sa.String(255), nullable=True),
        sa.Column('teams_upn',      sa.String(255), nullable=True),
        sa.Column('user_object_id', sa.String(255), nullable=True),
        sa.Column('forward_to',     sa.String(50),  nullable=False),
        sa.Column('activate_at',    sa.DateTime(),  nullable=False),
        sa.Column('deactivate_at',  sa.DateTime(),  nullable=True),
        sa.Column('is_active',      sa.Boolean(),  nullable=True),
        sa.Column('activated',      sa.Boolean(),  nullable=True),
        sa.Column('deactivated',    sa.Boolean(),  nullable=True),
        sa.Column('created_at',     sa.DateTime(), nullable=True),
        sa.Column('created_by',     sa.String(80),  nullable=True),
        sa.Column('note',           sa.String(200), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('time_window_schedules',
        sa.Column('id',              sa.Integer(),  nullable=False),
        sa.Column('name',            sa.String(100), nullable=True),
        sa.Column('platform',        sa.String(20),  nullable=False),
        sa.Column('user_id',         sa.String(255), nullable=True),
        sa.Column('user_upn',        sa.String(255), nullable=True),
        sa.Column('display_name',    sa.String(255), nullable=True),
        sa.Column('teams_upn',       sa.String(255), nullable=True),
        sa.Column('user_object_id',  sa.String(255), nullable=True),
        sa.Column('forward_to',      sa.String(50),  nullable=False),
        sa.Column('days',            sa.String(100), nullable=False),
        sa.Column('start_time',      sa.String(10),  nullable=False),
        sa.Column('end_time',        sa.String(10),  nullable=False),
        sa.Column('note',            sa.String(200), nullable=True),
        sa.Column('is_enabled',      sa.Boolean(),  nullable=True),
        sa.Column('cf_active',       sa.Boolean(),  nullable=True),
        sa.Column('last_checked',    sa.DateTime(), nullable=True),
        sa.Column('last_action',     sa.String(200), nullable=True),
        sa.Column('created_at',      sa.DateTime(), nullable=True),
        sa.Column('created_by',      sa.String(80),  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('audit_logs',
        sa.Column('id',          sa.Integer(),  nullable=False),
        sa.Column('timestamp',   sa.DateTime(), nullable=False),
        sa.Column('username',    sa.String(80),  nullable=False),
        sa.Column('user_role',   sa.String(20),  nullable=True),
        sa.Column('action',      sa.String(50),  nullable=False),
        sa.Column('resource',    sa.String(50),  nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('detail',      sa.String(500), nullable=True),
        sa.Column('ip_address',  sa.String(45),  nullable=True),
        sa.Column('status',      sa.String(10),  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('cert_domains',
        sa.Column('id',               sa.Integer(),  nullable=False),
        sa.Column('hostname',         sa.String(255), nullable=False),
        sa.Column('port',             sa.Integer(),  nullable=True),
        sa.Column('label',            sa.String(120), nullable=True),
        sa.Column('notify_days',      sa.Integer(),  nullable=True),
        sa.Column('is_active',        sa.Boolean(),  nullable=True),
        sa.Column('added_by',         sa.String(80),  nullable=True),
        sa.Column('created_at',       sa.DateTime(), nullable=True),
        sa.Column('private_key_pem',  sa.Text(),     nullable=True),
        sa.Column('csr_pem',          sa.Text(),     nullable=True),
        sa.Column('csr_cn',           sa.String(255), nullable=True),
        sa.Column('csr_org',          sa.String(255), nullable=True),
        sa.Column('csr_ou',           sa.String(255), nullable=True),
        sa.Column('csr_country',      sa.String(5),   nullable=True),
        sa.Column('csr_state',        sa.String(100), nullable=True),
        sa.Column('csr_locality',     sa.String(100), nullable=True),
        sa.Column('csr_sans',         sa.Text(),     nullable=True),
        sa.Column('csr_generated_at', sa.DateTime(), nullable=True),
        sa.Column('cert_chain_pem',   sa.Text(),     nullable=True),
        sa.Column('cert_uploaded_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('cert_devices',
        sa.Column('id',               sa.Integer(),  nullable=False),
        sa.Column('product_type',     sa.String(30),  nullable=False),
        sa.Column('label',            sa.String(120), nullable=True),
        sa.Column('hostname',         sa.String(255), nullable=False),
        sa.Column('port',             sa.Integer(),  nullable=True),
        sa.Column('ip_address',       sa.String(100), nullable=True),
        sa.Column('username',         sa.String(255), nullable=True),
        sa.Column('password',         sa.String(255), nullable=True),
        sa.Column('transport',        sa.String(10),  nullable=True),
        sa.Column('sip_port',         sa.Integer(),  nullable=True),
        sa.Column('mgmt_port',        sa.Integer(),  nullable=True),
        sa.Column('api_endpoint',     sa.String(255), nullable=True),
        sa.Column('snmp_community',   sa.String(100), nullable=True),
        sa.Column('is_active',        sa.Boolean(),  nullable=True),
        sa.Column('notify_days',      sa.Integer(),  nullable=True),
        sa.Column('added_by',         sa.String(80),  nullable=True),
        sa.Column('created_at',       sa.DateTime(), nullable=True),
        sa.Column('private_key_pem',  sa.Text(),     nullable=True),
        sa.Column('csr_pem',          sa.Text(),     nullable=True),
        sa.Column('csr_cn',           sa.String(255), nullable=True),
        sa.Column('csr_org',          sa.String(255), nullable=True),
        sa.Column('csr_ou',           sa.String(255), nullable=True),
        sa.Column('csr_country',      sa.String(5),   nullable=True),
        sa.Column('csr_state',        sa.String(100), nullable=True),
        sa.Column('csr_locality',     sa.String(100), nullable=True),
        sa.Column('csr_sans',         sa.Text(),     nullable=True),
        sa.Column('csr_generated_at', sa.DateTime(), nullable=True),
        sa.Column('cert_chain_pem',   sa.Text(),     nullable=True),
        sa.Column('cert_uploaded_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('cert_results',
        sa.Column('id',          sa.Integer(),  nullable=False),
        sa.Column('domain_id',   sa.Integer(),  nullable=True),
        sa.Column('device_id',   sa.Integer(),  nullable=True),
        sa.Column('risk',        sa.String(20),  nullable=True),
        sa.Column('days_left',   sa.Integer(),  nullable=True),
        sa.Column('not_before',  sa.String(20),  nullable=True),
        sa.Column('not_after',   sa.String(20),  nullable=True),
        sa.Column('issuer_org',  sa.String(200), nullable=True),
        sa.Column('issuer_cn',   sa.String(200), nullable=True),
        sa.Column('subject_cn',  sa.String(200), nullable=True),
        sa.Column('san_count',   sa.Integer(),  nullable=True),
        sa.Column('error',       sa.String(500), nullable=True),
        sa.Column('checked_at',  sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['domain_id'], ['cert_domains.id']),
        sa.ForeignKeyConstraint(['device_id'], ['cert_devices.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('did_countries',
        sa.Column('id',         sa.Integer(),  nullable=False),
        sa.Column('name',       sa.String(120), nullable=False),
        sa.Column('iso_code',   sa.String(5),   nullable=True),
        sa.Column('notes',      sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(80),  nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    op.create_table('did_regions',
        sa.Column('id',         sa.Integer(),  nullable=False),
        sa.Column('country_id', sa.Integer(),  nullable=False),
        sa.Column('name',       sa.String(120), nullable=False),
        sa.Column('notes',      sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('created_by', sa.String(80),  nullable=True),
        sa.ForeignKeyConstraint(['country_id'], ['did_countries.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('country_id', 'name', name='uq_region_country_name')
    )

    op.create_table('did_blocks',
        sa.Column('id',           sa.Integer(),  nullable=False),
        sa.Column('country_id',   sa.Integer(),  nullable=False),
        sa.Column('region_id',    sa.Integer(),  nullable=True),
        sa.Column('label',        sa.String(100), nullable=True),
        sa.Column('start_number', sa.String(30),  nullable=False),
        sa.Column('end_number',   sa.String(30),  nullable=False),
        sa.Column('number_type',  sa.String(30),  nullable=True),
        sa.Column('notes',        sa.String(255), nullable=True),
        sa.Column('created_at',   sa.DateTime(), nullable=True),
        sa.Column('created_by',   sa.String(80),  nullable=True),
        sa.ForeignKeyConstraint(['country_id'], ['did_countries.id']),
        sa.ForeignKeyConstraint(['region_id'],  ['did_regions.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table('phone_numbers',
        sa.Column('id',            sa.Integer(),  nullable=False),
        sa.Column('number',        sa.String(50),  nullable=False),
        sa.Column('number_norm',   sa.String(50),  nullable=False),
        sa.Column('platform',      sa.String(20),  nullable=False),
        sa.Column('status',        sa.String(20),  nullable=True),
        sa.Column('assigned_to',   sa.String(255), nullable=True),
        sa.Column('assigned_type', sa.String(50),  nullable=True),
        sa.Column('number_type',   sa.String(50),  nullable=True),
        sa.Column('location',      sa.String(255), nullable=True),
        sa.Column('synced_at',     sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('number_norm', 'platform', name='uq_number_platform')
    )

    op.create_table('inventory_sync_logs',
        sa.Column('id',          sa.Integer(),  nullable=False),
        sa.Column('platform',    sa.String(20),  nullable=False),
        sa.Column('started_at',  sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('total',       sa.Integer(),  nullable=True),
        sa.Column('status',      sa.String(20),  nullable=True),
        sa.Column('error',       sa.String(500), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('inventory_sync_logs')
    op.drop_table('phone_numbers')
    op.drop_table('did_blocks')
    op.drop_table('did_regions')
    op.drop_table('did_countries')
    op.drop_table('cert_results')
    op.drop_table('cert_devices')
    op.drop_table('cert_domains')
    op.drop_table('audit_logs')
    op.drop_table('time_window_schedules')
    op.drop_table('schedules')
    op.drop_table('sites')
    op.drop_table('smtp_config')
    op.drop_table('cucm_config')
    op.drop_table('webex_config')
    op.drop_table('ms_graph_config')
    op.drop_table('users')
    op.drop_table('ldap_servers')
    op.drop_table('platform_settings')
