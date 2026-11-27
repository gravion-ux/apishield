"""Optional paid-tier feature gate.

The free gateway is complete without this module: every detector rule runs
in the free build. Paid features (hosted event dashboard, managed rule
updates, priority support) are delivered as services around the gateway,
not by disabling free functionality. This gate only records whether the
operator has opted into a paid plan through the environment, so future
paid-only integrations can check one place instead of scattering flags.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

PRO_ENV_VAR = "APISHIELD_PRO"
_TRUTHY = {"1", "true", "yes", "on"}


def pro_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """True only when the operator explicitly opts into the paid tier."""
    env = os.environ if environ is None else environ
    return env.get(PRO_ENV_VAR, "").strip().lower() in _TRUTHY
