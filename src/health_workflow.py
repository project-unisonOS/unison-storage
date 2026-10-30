"""Compatibility entry point for the bounded synthetic health workflow."""
from source_workflow import SourceWorkflow, initialize_authority as initialize_source_authority

VERSION = "synthetic-health-workflow.v1"

def initialize_authority(path, key):
    return initialize_source_authority(path, key, schema=VERSION)

class HealthWorkflow(SourceWorkflow):
    policy_version = VERSION
    id_prefix = "health_"
    legacy_adapter_id = "synthetic-health-export.v1"
    def __init__(self, root, authority_path, key):
        super().__init__(root, authority_path, key, "synthetic-health-export.v1")
