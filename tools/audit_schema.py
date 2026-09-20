"""audit_schema.py - JSON Schema and data models for marketplace issue analysis."""

EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "chunk_id": {"type": "integer"},
        "issues_analyzed": {"type": "integer"},
        "records": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "issue_number": {"type": "integer"},
                    "type": {
                        "type": "string",
                        "enum": ["submission", "verification_update", "bug_report", "discussion", "other"]
                    },
                    "plugin_id": {"type": ["string", "null"]},
                    "plugin_name": {"type": ["string", "null"]},
                    "repo_url": {"type": ["string", "null"]},
                    "author": {"type": "string"},
                    "outcome": {
                        "type": "string",
                        "enum": ["approved_published", "needs_fixes_stalled", "rejected", "in_review", "not_applicable"]
                    },
                    "bot_validation_errors": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "bot_capabilities_flagged": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "manual_review_blockers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "reviewer": {"type": "string"},
                                "category": {
                                    "type": "string",
                                    "enum": [
                                        "agent_steering_files",
                                        "undeclared_dependencies",
                                        "unapproved_scripts_or_binaries",
                                        "qml_wayland_quality",
                                        "licensing_or_assets",
                                        "other"
                                    ]
                                },
                                "detail": {"type": "string"},
                                "resolution": {"type": "string"}
                            },
                            "required": ["reviewer", "category", "detail"]
                        }
                    },
                    "key_takeaway": {"type": "string"}
                },
                "required": ["issue_number", "type", "outcome"]
            }
        }
    },
    "required": ["chunk_id", "issues_analyzed", "records"]
}
