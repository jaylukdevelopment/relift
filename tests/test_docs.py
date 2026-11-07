"""The documentation is part of the product: its links and index are checked here.

A dead relative link in a README is the same class of bug as a technique missing
from the catalogue — the document claims something the repository does not have.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ROOT_DOCS = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
)

# [text](target) — the documentation never uses reference-style links.
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def markdown_files() -> list[Path]:
    files = [ROOT / name for name in ROOT_DOCS]
    files += sorted(DOCS.glob("*.md"))
    return [path for path in files if path.is_file()]


def relative_targets(path: Path) -> list[str]:
    targets = []
    for match in LINK.finditer(path.read_text(encoding="utf-8")):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        targets.append(target.split("#", 1)[0])
    return [target for target in targets if target]


def test_every_relative_link_resolves():
    broken = []
    for path in markdown_files():
        for target in relative_targets(path):
            if not (path.parent / target).resolve().exists():
                broken.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not broken, "dead documentation links:\n" + "\n".join(broken)


def test_every_document_is_indexed():
    index = (DOCS / "README.md").read_text(encoding="utf-8")
    missing = [
        path.name
        for path in sorted(DOCS.glob("*.md"))
        if path.name != "README.md" and path.name not in index
    ]
    assert not missing, f"documents missing from docs/README.md: {missing}"


def test_readme_lists_every_document():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    missing = [
        path.name
        for path in sorted(DOCS.glob("*.md"))
        if path.name != "README.md" and f"docs/{path.name}" not in readme
    ]
    assert not missing, f"documents missing from the README table: {missing}"


def test_no_document_points_at_a_dead_host():
    # The lab path is canonical; a relift.* hostname never existed.
    offenders = [
        str(path.relative_to(ROOT))
        for path in markdown_files()
        if "relift.pixelcity.dev" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"documents link to a host that does not resolve: {offenders}"
