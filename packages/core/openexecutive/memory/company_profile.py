from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class TargetCustomer(BaseModel):
    profile: str = ""
    pain_points: list[str] = Field(default_factory=list)


class CompetitiveLandscape(BaseModel):
    primary_competitors: list[str] = Field(default_factory=list)
    competitive_advantages: list[str] = Field(default_factory=list)


class OrgStructure(BaseModel):
    departments: list[str] = Field(default_factory=list)
    leadership_team: list[str] = Field(default_factory=list)


class StrategicPriorities(BaseModel):
    current_year: list[str] = Field(default_factory=list)
    north_star_metric: str = ""


class Culture(BaseModel):
    values: list[str] = Field(default_factory=list)
    operating_principles: list[str] = Field(default_factory=list)


class Financials(BaseModel):
    burn_rate_monthly: float | None = None
    runway_months: float | None = None
    key_metrics: dict[str, Any] = Field(default_factory=dict)


class CompanyProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str = ""
    industry: str = ""
    stage: str = ""
    founding_year: int | None = None
    headcount: int | None = None
    annual_revenue_arr: float | None = None
    mission: str = ""
    vision: str = ""
    target_customer: TargetCustomer = Field(default_factory=TargetCustomer)
    competitive_landscape: CompetitiveLandscape = Field(
        default_factory=CompetitiveLandscape
    )
    org_structure: OrgStructure = Field(default_factory=OrgStructure)
    strategic_priorities: StrategicPriorities = Field(
        default_factory=StrategicPriorities
    )
    culture: Culture = Field(default_factory=Culture)
    financials: Financials = Field(default_factory=Financials)

    @classmethod
    def load_from_yaml(cls, path: Path | str) -> CompanyProfile:
        path = Path(path)
        if not path.exists():
            return cls()
        # Explicit UTF-8: profile.yaml is routinely hand-edited, so it can hold
        # real non-ASCII text. Without this, the platform default (cp1252 on
        # Windows) silently mojibakes it into the cached company-profile prompt
        # block rather than raising.
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        company_data = data.get("company", data)
        return cls.model_validate(company_data)

    def save_to_yaml(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"company": self.model_dump()}
        # Write-then-rename so a failure mid-dump (disk full, unrepresentable
        # value) can never leave a truncated profile behind: every other
        # subsystem loads this file, and callers such as the onboarding
        # route roll back on failure assuming the old profile survived.
        #
        # - O_EXCL via `opener`: the temp name is created fresh and never
        #   follows a pre-planted symlink. Going through open() (not
        #   os.fdopen) keeps the explicit-encoding contract visible.
        # - A random component plus O_EXCL: two processes on one volume
        #   (both PID 1 in their containers) cannot collide.
        # - The destination's mode is carried over: rename creates a new
        #   inode, so a file an operator chmod'd 0600 would otherwise
        #   silently revert to the umask default.
        # - fsync file and directory: a hard crash between write and
        #   rename must not leave a zero-length profile.
        # Stale temps from an earlier crash are swept first so a
        # 0644 copy of the financials never lingers in company/.
        for stale in path.parent.glob(f".tmp-*-{path.name}"):
            with contextlib.suppress(OSError):
                stale.unlink()
        tmp_path = path.with_name(f".tmp-{os.getpid()}-{secrets.token_hex(4)}-{path.name}")
        existing_mode: int | None = None
        with contextlib.suppress(OSError):
            existing_mode = stat.S_IMODE(path.stat().st_mode)

        def _exclusive(p: str, flags: int) -> int:
            return os.open(p, flags | os.O_EXCL, 0o600 if existing_mode is None else existing_mode)

        try:
            with open(tmp_path, "w", encoding="utf-8", opener=_exclusive) as f:
                if existing_mode is not None:
                    os.fchmod(f.fileno(), existing_mode)
                yaml.dump(data, f, default_flow_style=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            with contextlib.suppress(OSError):
                dir_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

    def to_prompt_block(self) -> str:
        if not self.name:
            return ""

        lines = ["## Company Context", ""]
        lines.append(f"**Company**: {self.name}")
        if self.industry:
            lines.append(f"**Industry**: {self.industry}")
        if self.stage:
            lines.append(f"**Stage**: {self.stage}")
        if self.founding_year:
            lines.append(f"**Founded**: {self.founding_year}")
        if self.headcount:
            lines.append(f"**Headcount**: {self.headcount}")
        if self.annual_revenue_arr:
            lines.append(f"**ARR**: ${self.annual_revenue_arr:,.0f}")

        if self.mission:
            lines.extend(["", f"**Mission**: {self.mission}"])
        if self.vision:
            lines.append(f"**Vision**: {self.vision}")

        if self.target_customer.profile:
            lines.extend(["", "**Target Customer**:"])
            lines.append(f"  {self.target_customer.profile}")
            if self.target_customer.pain_points:
                lines.append("  Pain points: " + "; ".join(self.target_customer.pain_points))

        if self.competitive_landscape.primary_competitors:
            lines.extend(["", "**Competitive Landscape**:"])
            lines.append(
                "  Competitors: " + ", ".join(self.competitive_landscape.primary_competitors)
            )
            if self.competitive_landscape.competitive_advantages:
                lines.append(
                    "  Our advantages: "
                    + "; ".join(self.competitive_landscape.competitive_advantages)
                )

        if self.strategic_priorities.current_year:
            lines.extend(["", "**Strategic Priorities (Current Year)**:"])
            for p in self.strategic_priorities.current_year:
                lines.append(f"  - {p}")
            if self.strategic_priorities.north_star_metric:
                lines.append(
                    f"  North Star: {self.strategic_priorities.north_star_metric}"
                )

        if self.culture.values:
            lines.extend(["", f"**Values**: {', '.join(self.culture.values)}"])

        if self.financials.burn_rate_monthly is not None:
            lines.extend(["", "**Financial Position**:"])
            lines.append(
                f"  Monthly burn: ${self.financials.burn_rate_monthly:,.0f}"
            )
            if self.financials.runway_months is not None:
                lines.append(f"  Runway: {self.financials.runway_months:.1f} months")
            for k, v in self.financials.key_metrics.items():
                lines.append(f"  {k}: {v}")

        if self.org_structure.leadership_team:
            lines.extend(["", "**Leadership**: " + ", ".join(self.org_structure.leadership_team)])

        return "\n".join(lines)

    def is_empty(self) -> bool:
        return not bool(self.name)
