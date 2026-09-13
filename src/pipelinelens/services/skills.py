"""Versioned diagnostic skill packs used as transparent curated RAG sources."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML


@dataclass(frozen=True, slots=True)
class SkillPack:
    skill_id: str
    version: int
    title: str
    categories: tuple[str, ...]
    required_evidence: tuple[str, ...]
    safe_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    runbook: str

    @property
    def evidence_id(self) -> str:
        return f"skill:{self.skill_id}:v{self.version}"


def _default_skill_directory() -> Path:
    configured = os.getenv("PIPELINELENS_SKILLS_DIR")
    if configured:
        return Path(configured)
    project_root = Path(__file__).resolve().parents[3]
    return project_root / "skills"


def load_skill_packs(directory: Path | None = None) -> list[SkillPack]:
    """Load public, version-controlled skill packs from the repository."""

    skill_directory = directory or _default_skill_directory()
    yaml = YAML(typ="safe")
    packs: list[SkillPack] = []
    for manifest_path in sorted(skill_directory.glob("*/skill.yaml")):
        payload = yaml.load(manifest_path.read_text(encoding="utf-8")) or {}
        runbook_path = manifest_path.with_name("runbook.md")
        packs.append(
            SkillPack(
                skill_id=str(payload["id"]),
                version=int(payload.get("version", 1)),
                title=str(payload["title"]),
                categories=tuple(str(item) for item in payload.get("categories", [])),
                required_evidence=tuple(str(item) for item in payload.get("required_evidence", [])),
                safe_actions=tuple(str(item) for item in payload.get("safe_actions", [])),
                prohibited_actions=tuple(
                    str(item) for item in payload.get("prohibited_actions", [])
                ),
                runbook=runbook_path.read_text(encoding="utf-8") if runbook_path.exists() else "",
            )
        )
    return packs


def matching_skill_packs(category: str, directory: Path | None = None) -> list[SkillPack]:
    return [pack for pack in load_skill_packs(directory) if category in pack.categories]
