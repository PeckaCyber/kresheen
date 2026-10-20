"""Guard against YAML alias ("billion laughs") expansion in uploaded manifests.

`yaml.safe_load` keeps aliases as shared references, so loading is cheap, but the moment anything walks or
serialises the result, each level of aliases multiplies the work by its fan-out: a ~600 byte file nested 8 levels
took 16 s and every extra level is 9x more. Kubernetes manifests do not use aliases, so
a document with more than a handful is refused rather than loaded. The repository path already skipped such
files; this is the same rule for uploads.
"""

from __future__ import annotations

import re

MAX_YAML_ALIASES = 20
_ALIAS_RE = re.compile(r"(?m)(?:^|[\s:\[,{-])\*[A-Za-z0-9_-]+")


def check_yaml_aliases(text: str) -> None:
    """Raises ValueError (shown to the user as the run's error) when the text has too many aliases."""
    if len(_ALIAS_RE.findall(text)) > MAX_YAML_ALIASES:
        raise ValueError(
            f"The file uses more than {MAX_YAML_ALIASES} YAML aliases (*name). Kubernetes manifests do not need them "
            "and they can be used to exhaust the server, so the file was refused. Expand the aliases and upload it again."
        )
