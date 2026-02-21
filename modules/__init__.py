"""
nexsus/modules/__init__.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Module registry — import all scan modules for use by the orchestrator.
"""
from .passive_recon   import PassiveRecon
from .active_recon    import ActiveRecon
from .vuln_detection  import VulnScan
from .fuzzing         import Fuzzing
from .api_security    import APISecurity
from .auth_testing    import AuthTesting
from .cloud_misconfig import CloudMisconfig
from .competition     import CompetitionMode
from .waf_bypass      import WAFBypassEngine
from .learning_engine import LearningEngine

__all__ = [
    "PassiveRecon",
    "ActiveRecon",
    "VulnScan",
    "Fuzzing",
    "APISecurity",
    "AuthTesting",
    "CloudMisconfig",
    "CompetitionMode",
    "WAFBypassEngine",
    "LearningEngine",
]
