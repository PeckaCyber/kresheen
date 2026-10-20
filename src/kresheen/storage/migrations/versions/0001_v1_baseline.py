"""v1 baseline: the core schema as of the first public release.

Revision ID: 0001_v1_baseline
Revises: (none)
Create Date: 2026-10-15

This revision is frozen. Never edit it after release; add a new revision instead.
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_v1_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("action_statuses",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("action_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("action_statuses", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_action_statuses_action_id"), ["action_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_action_statuses_application_id"), ["application_id"], unique=False)

    op.create_table("agent_configs",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("scope", sa.String(), nullable=True),
    sa.Column("scope_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("agent_configs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_agent_configs_scope"), ["scope"], unique=False)
        batch_op.create_index(batch_op.f("ix_agent_configs_scope_id"), ["scope_id"], unique=False)

    op.create_table("api_tokens",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("token_hash", sa.String(), nullable=True),
    sa.Column("user_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("api_tokens", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_api_tokens_token_hash"), ["token_hash"], unique=True)
        batch_op.create_index(batch_op.f("ix_api_tokens_user_id"), ["user_id"], unique=False)

    op.create_table("application_groups",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("owner_user_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("application_groups", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_application_groups_owner_user_id"), ["owner_user_id"], unique=False)

    op.create_table("applications",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("owner_user_id", sa.String(), nullable=True),
    sa.Column("status", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("applications", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_applications_owner_user_id"), ["owner_user_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_applications_status"), ["status"], unique=False)

    op.create_table("asset_flows",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("run_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("asset_flows", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_asset_flows_run_id"), ["run_id"], unique=False)

    op.create_table("assets",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("source", sa.String(), nullable=True),
    sa.Column("run_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("assets", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_assets_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_assets_source"), ["source"], unique=False)

    op.create_table("audit_events",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("user_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("audit_events", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_audit_events_at"), ["at"], unique=False)
        batch_op.create_index(batch_op.f("ix_audit_events_user_id"), ["user_id"], unique=False)

    op.create_table("data_source_configs",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("data_source_configs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_data_source_configs_application_id"), ["application_id"], unique=False)

    op.create_table("diagram_element_layouts",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("diagram_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("diagram_element_layouts", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_diagram_element_layouts_diagram_id"), ["diagram_id"], unique=False)

    op.create_table("diagrams",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("diagrams", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_diagrams_application_id"), ["application_id"], unique=False)

    op.create_table("element_properties",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("element_properties", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_element_properties_application_id"), ["application_id"], unique=False)

    op.create_table("encrypted_secrets",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("owner_scope", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("encrypted_secrets", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_encrypted_secrets_owner_scope"), ["owner_scope"], unique=False)

    op.create_table("fact_edges",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("run_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("fact_edges", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_fact_edges_run_id"), ["run_id"], unique=False)

    op.create_table("fact_nodes",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("run_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("fact_nodes", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_fact_nodes_run_id"), ["run_id"], unique=False)

    op.create_table("findings",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("domain", sa.String(), nullable=True),
    sa.Column("status", sa.String(), nullable=True),
    sa.Column("asset_id", sa.String(), nullable=True),
    sa.Column("source_tool", sa.String(), nullable=True),
    sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("run_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_asset_id"), ["asset_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_discovered_at"), ["discovered_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_domain"), ["domain"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_run_id"), ["run_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_source_tool"), ["source_tool"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_status"), ["status"], unique=False)

    op.create_table("instance_settings",
    sa.Column("key", sa.String(), nullable=False),
    sa.Column("value", sa.JSON(), nullable=True),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("updated_by", sa.String(), nullable=True),
    sa.PrimaryKeyConstraint("key")
    )
    op.create_table("manual_flows",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("manual_flows", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_manual_flows_application_id"), ["application_id"], unique=False)

    op.create_table("manual_threats",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("manual_threats", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_manual_threats_application_id"), ["application_id"], unique=False)

    op.create_table("sessions",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("user_id", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_sessions_expires_at"), ["expires_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_sessions_user_id"), ["user_id"], unique=False)

    op.create_table("threat_kb_entries",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("source", sa.String(), nullable=True),
    sa.Column("is_active", sa.Boolean(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("threat_kb_entries", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_threat_kb_entries_is_active"), ["is_active"], unique=False)
        batch_op.create_index(batch_op.f("ix_threat_kb_entries_source"), ["source"], unique=False)

    op.create_table("threat_model_runs",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("status", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("threat_model_runs", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_threat_model_runs_application_id"), ["application_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_threat_model_runs_status"), ["status"], unique=False)

    op.create_table("threat_snapshots",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("day", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("threat_snapshots", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_threat_snapshots_application_id"), ["application_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_threat_snapshots_day"), ["day"], unique=False)

    op.create_table("threat_statuses",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("threat_key", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("threat_statuses", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_threat_statuses_application_id"), ["application_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_threat_statuses_threat_key"), ["threat_key"], unique=False)

    op.create_table("trust_boundary_assignments",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("component_name", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("trust_boundary_assignments", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_trust_boundary_assignments_application_id"), ["application_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_trust_boundary_assignments_component_name"), ["component_name"], unique=False)

    op.create_table("trust_boundary_layouts",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("application_id", sa.String(), nullable=True),
    sa.Column("boundary_name", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("trust_boundary_layouts", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_trust_boundary_layouts_application_id"), ["application_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_trust_boundary_layouts_boundary_name"), ["boundary_name"], unique=False)

    op.create_table("users",
    sa.Column("id", sa.String(), nullable=False),
    sa.Column("email", sa.String(), nullable=True),
    sa.Column("data", sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint("id")
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_users_email"), ["email"], unique=True)

