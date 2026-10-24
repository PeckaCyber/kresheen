"""Hypothesis profiles for the fuzz tests.

`ci` (the default) runs a few hundred examples per test so the normal suite stays fast. The nightly security job
sets HYPOTHESIS_PROFILE=nightly for a much longer run. No example database is written: CI runners are thrown away,
and a failure prints the input that reproduces it.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "ci", max_examples=150, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile(
    "nightly", max_examples=5000, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
