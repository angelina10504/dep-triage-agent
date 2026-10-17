"""Step 01 - Collect the details: parse a requirements.txt into Dependency records."""
from __future__ import annotations

import re

from packaging.utils import canonicalize_name

from .models import Dependency

# name, optional [extras], then the version specifier part
_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT_PIN = re.compile(r"^==\s*([^\s,;]+)\s*$")


def parse_requirements(text: str, ecosystem: str = "PyPI") -> list[Dependency]:
    deps: list[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()        # drop comments
        if not line or line.startswith("-"):        # skip blanks and pip options (-r, -e, --index-url)
            continue
        line = line.split(";", 1)[0].strip()        # drop environment markers
        m = _LINE.match(line)
        if not m:
            continue
        raw_name, _extras, spec = m.groups()
        pin = _EXACT_PIN.match(spec.strip())
        version = pin.group(1) if pin else None     # only an exact == pin tells us the installed version
        name = canonicalize_name(raw_name)
        deps.append(
            Dependency(
                id=f"{ecosystem}:{name}@{version or 'unpinned'}#L{lineno}",
                name=name,
                raw_name=raw_name,
                version=version,
                line=lineno,
                spec=raw.strip(),
                ecosystem=ecosystem,
            )
        )
    return deps
