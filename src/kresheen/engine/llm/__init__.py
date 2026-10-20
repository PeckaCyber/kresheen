"""Experimental AI assist: guardrail policy, provider client and
the instance switch.

Every model call goes through `policy.run_llm_task`; nothing else in the codebase should talk to a
provider directly (the model picker's `list_models` is the one metadata-only exception).
"""
