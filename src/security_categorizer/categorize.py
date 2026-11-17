"""The categorization itself, following SP 800-60 Vol. 1 Rev. 1 Section 4:

1. Identify the information types (from the catalog, or custom ones you define).
2. Start from each type's provisional impact levels.
3. Adjust them where the system's context calls for it, with a written justification.
4. Take the high-water mark per objective across all types to get the system's
   security category (FIPS 199), then apply any system-level adjustments.

What happens next depends on the mode:

* federal (FIPS 199 / FIPS 200): the overall impact level is the highest of C, I
  and A (the FIPS 200 high-water mark), and it picks the SP 800-53B Low,
  Moderate or High baseline.
* nss (CNSSI 1253, 2022): C, I and A stay separate (for example M-M-L) and each
  one selects its own controls from CNSSI 1253 Appendix D; there is no overall level.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from security_categorizer.datasets import DataError, InfoType, InfoTypeCatalog
from security_categorizer.levels import OBJECTIVES, Level, high_water
from security_categorizer.system import AdjustmentSpec, CustomTypeSpec, SystemSpec

MODES = ("federal", "nss")


class CategorizationError(ValueError):
    """The system description can't be categorized as written."""


@dataclass(frozen=True)
class Adjustment:
    objective: str
    before: Level
    after: Level
    justification: str

    @property
    def direction(self) -> str:
        if self.after.rank > self.before.rank:
            return "raised"
        if self.after.rank < self.before.rank:
            return "lowered"
        return "unchanged"


@dataclass
class TypeResult:
    id: str
    title: str
    source: str  # dataset name, or the custom type's stated source
    provisional: dict[str, Level]
    final: dict[str, Level]
    adjustments: list[Adjustment] = field(default_factory=list)
    footnoted: tuple[str, ...] = ()


@dataclass
class Categorization:
    system_name: str
    mode: str
    processes_pii: bool
    types: list[TypeResult]
    high_water: dict[str, Level]  # per objective, before system-level adjustments
    system_adjustments: list[Adjustment]
    final: dict[str, Level]  # the system's security category
    warnings: list[str]
    overlays: list[str]

    @property
    def overall(self) -> Level:
        """FIPS 200 high-water mark. Meaningful in federal mode only."""
        return high_water(self.final.values())

    @property
    def trigraph(self) -> str:
        """CNSSI 1253 notation, e.g. M-M-L (confidentiality-integrity-availability)."""
        return "-".join(self.final[o].letter for o in OBJECTIVES)

    @property
    def fips199_statement(self) -> str:
        parts = ", ".join(f"({o}, {self.final[o].value.upper()})" for o in OBJECTIVES)
        return f"SC {self.system_name} = {{{parts}}}"


def _adjust(current: Level, spec: AdjustmentSpec, where: str, warnings: list[str]) -> tuple[Level, Adjustment]:
    if not spec.justification.strip():
        raise CategorizationError(f"{where}: the {spec.objective} adjustment needs a justification")
    adj = Adjustment(spec.objective, current, spec.level, spec.justification.strip())
    if adj.direction == "unchanged":
        warnings.append(f"{where}: {spec.objective} adjustment to {spec.level.value} matches the current level")
    elif adj.direction == "lowered":
        warnings.append(
            f"{where}: {spec.objective} lowered from {current.value} to {spec.level.value}; "
            "lowering a provisional level should be reviewed and approved"
        )
    return spec.level, adj


def _resolve(entry, catalog: InfoTypeCatalog) -> tuple[str, str, str, dict[str, Level], tuple[str, ...]]:
    if isinstance(entry.ref, CustomTypeSpec):
        c = entry.ref
        return c.id, c.title, c.source, dict(c.levels), ()
    try:
        t: InfoType = catalog.get(entry.ref)
    except DataError as exc:
        raise CategorizationError(str(exc)) from exc
    return t.id, t.title, catalog.name, {o: t.provisional(o) for o in OBJECTIVES}, t.footnoted


def categorize(spec: SystemSpec, catalog: InfoTypeCatalog) -> Categorization:
    if spec.mode not in MODES:
        raise CategorizationError(f"mode must be one of {', '.join(MODES)} (got {spec.mode!r})")
    if not spec.information_types:
        raise CategorizationError("list at least one information type")
    warnings: list[str] = []
    results: list[TypeResult] = []
    seen: set[str] = set()
    for entry in spec.information_types:
        tid, title, source, provisional, footnoted = _resolve(entry, catalog)
        if tid in seen:
            raise CategorizationError(f"information type {tid} is listed twice")
        seen.add(tid)
        final = dict(provisional)
        adjustments = []
        for adj_spec in entry.adjustments:
            final[adj_spec.objective], adj = _adjust(final[adj_spec.objective], adj_spec, tid, warnings)
            adjustments.append(adj)
        for obj in footnoted:
            if not any(a.objective == obj for a in adjustments):
                warnings.append(
                    f"{tid}: SP 800-60 footnotes the provisional {obj} level with an exception; "
                    "check whether it applies to this system"
                )
        results.append(TypeResult(tid, title, source, provisional, final, adjustments, footnoted))

    # A system objective is never below low (FIPS 199: not-applicable can't apply to a system).
    water = {o: high_water((r.final[o] for r in results), floor=Level.LOW) for o in OBJECTIVES}
    final = dict(water)
    system_adjustments = []
    for adj_spec in spec.system_adjustments:
        if adj_spec.level.rank < water[adj_spec.objective].rank:
            raise CategorizationError(
                f"system-level {adj_spec.objective} can't be lowered to {adj_spec.level.value}: the high-water mark "
                f"of its information types is {water[adj_spec.objective].value} (and FIPS 199 never allows a system "
                "objective below low). Adjust the information type instead."
            )
        final[adj_spec.objective], adj = _adjust(final[adj_spec.objective], adj_spec, "system", warnings)
        system_adjustments.append(adj)

    overlays = list(spec.overlays)
    if spec.mode == "nss" and spec.processes_pii and "privacy" not in overlays:
        overlays.insert(0, "privacy")
    if spec.mode == "federal" and overlays:
        warnings.append("overlays are a CNSSI 1253 (nss mode) concept; they are listed but not applied in federal mode")

    return Categorization(
        system_name=spec.name,
        mode=spec.mode,
        processes_pii=spec.processes_pii,
        types=results,
        high_water=water,
        system_adjustments=system_adjustments,
        final=final,
        warnings=warnings,
        overlays=overlays,
    )
