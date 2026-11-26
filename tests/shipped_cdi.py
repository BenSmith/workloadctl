"""Which shipped bundles the generator refuses when their gpu resolves to
nvidia (validation.cdi_errors), so a render pinned to nvidia, the
deployment target, can tell a refused bundle from a missing unit."""

import os
import tomllib
from pathlib import Path
from unittest import mock

GPU = "nvidia"


def cdi_refused(config: dict) -> bool:
    import validation
    with mock.patch.dict(os.environ, {"WORKLOAD_GPU_OVERRIDE": GPU}):
        return bool(validation.cdi_errors(config))


def cdi_refused_toml(path: Path) -> bool:
    return cdi_refused(tomllib.loads(Path(path).read_text()))
