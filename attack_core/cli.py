"""
CLI entry point for attack-v19-core.

Usage:
    attack-v19 lookup T1059          Show technique details
    attack-v19 revoked               List all revoked IDs and replacements
    attack-v19 navigator --output layer.json   Generate Navigator layer JSON
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from .constants import (
    LEGACY_TECHNIQUE_REMAPS,
    V19_RELEASE_REVOCATION_MAP,
    V19_REVOCATION_MAP,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-v19",
        description="MITRE ATT&CK v19 lookup and utility CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # lookup
    lookup_parser = subparsers.add_parser(
        "lookup", help="Look up a technique by ATT&CK ID (e.g. T1059)"
    )
    lookup_parser.add_argument(
        "technique_id", help="ATT&CK technique ID (e.g. T1059, T1059.001)"
    )
    lookup_parser.add_argument(
        "--json", action="store_true", dest="as_json", help="Output as JSON"
    )

    # revoked
    subparsers.add_parser("revoked", help="List supported technique ID remaps")

    # navigator
    nav_parser = subparsers.add_parser(
        "navigator", help="Generate an ATT&CK Navigator layer JSON"
    )
    nav_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (default: stdout)",
    )
    nav_parser.add_argument(
        "--name",
        default="attack-v19-core",
        help="Layer name (default: attack-v19-core)",
    )
    nav_parser.add_argument(
        "--domain",
        choices=["enterprise", "mobile", "ics"],
        default="enterprise",
        help="ATT&CK domain (default: enterprise)",
    )

    return parser


def _load_index():
    """Load ATTACKIndex. Provides a clear error if STIX data is missing."""
    from .index import ATTACKIndex
    from .loader import ATTACKLoader

    try:
        loader = ATTACKLoader()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        print(
            "\nTo download STIX data, run:\n"
            "  python -m attack_core.download\n"
            "  # or: python scripts/download_attack_data.py",
            file=sys.stderr,
        )
        sys.exit(1)
    return ATTACKIndex(loader)


def cmd_lookup(args: argparse.Namespace) -> int:
    """Look up a technique by ID and display its details."""
    index = _load_index()
    technique = index.get(args.technique_id)

    if technique is None:
        # Check if it is a known remap even if the replacement is not loaded.
        replacement = V19_REVOCATION_MAP.get(args.technique_id)
        if replacement:
            classification = (
                "revoked in ATT&CK v19"
                if args.technique_id in V19_RELEASE_REVOCATION_MAP
                else "a legacy compatibility ID"
            )
            print(
                f"Technique {args.technique_id} is {classification}. "
                f"Replacement: {replacement}",
                file=sys.stderr,
            )
            print(
                f"Could not find replacement {replacement} in loaded data.",
                file=sys.stderr,
            )
        else:
            print(f"Technique {args.technique_id} not found.", file=sys.stderr)
        return 1

    if args.as_json:
        print(technique.model_dump_json(indent=2))
        return 0

    # Pretty-print
    resolved_id = index.resolve_attack_id(args.technique_id)
    normalized_id = args.technique_id.strip().replace("/", ".")
    was_remapped = resolved_id != normalized_id

    lines = []
    lines.append("-" * 60)
    if was_remapped:
        classification = (
            "V19 REVOCATION"
            if normalized_id in V19_RELEASE_REVOCATION_MAP
            else "LEGACY REMAP"
        )
        lines.append(f"  [!] {classification}: {args.technique_id} -> {resolved_id}")
    lines.append(f"  {technique.attack_id}: {technique.name}")
    lines.append("-" * 60)
    lines.append(f"  Domain:      {technique.domain.value}")
    if technique.is_subtechnique:
        lines.append(f"  Parent:      {technique.parent_id}")
    if technique.tactic_ids:
        lines.append(f"  Tactics:     {', '.join(technique.tactic_ids)}")
    if technique.platforms:
        lines.append(f"  Platforms:   {', '.join(technique.platforms)}")
    if technique.data_sources:
        lines.append(f"  Data Src:    {', '.join(technique.data_sources[:5])}")
        if len(technique.data_sources) > 5:
            lines.append(
                f"               ... and {len(technique.data_sources) - 5} more"
            )
    if technique.url:
        lines.append(f"  URL:         {technique.url}")
    lines.append("")

    # Description (truncated for terminal readability)
    desc = technique.description.strip()
    if desc:
        lines.append("  Description:")
        wrapped = textwrap.fill(
            desc[:500], width=70, initial_indent="    ", subsequent_indent="    "
        )
        lines.append(wrapped)
        if len(desc) > 500:
            lines.append(f"    ... ({len(desc)} chars total, use --json for full text)")

    # Sub-techniques
    if not technique.is_subtechnique:
        subs = index.get_subtechniques_of(technique.attack_id)
        if subs:
            lines.append("")
            lines.append(f"  Sub-techniques ({len(subs)}):")
            for sub in sorted(subs, key=lambda s: s.attack_id):
                lines.append(f"    {sub.attack_id}: {sub.name}")

    lines.append("-" * 60)
    print("\n".join(lines))
    return 0


def cmd_revoked(_args: argparse.Namespace) -> int:
    """List official v19 revocations and older compatibility aliases."""
    print(
        "Official ATT&CK v19 technique revocations "
        f"({len(V19_RELEASE_REVOCATION_MAP)} entries)"
    )
    print("-" * 50)
    print(f"  {'Revoked ID':<16} {'Replacement':<16}")
    print(f"  {'-' * 14}   {'-' * 14}")
    for old_id, new_id in sorted(V19_RELEASE_REVOCATION_MAP.items()):
        print(f"  {old_id:<16} -> {new_id:<16}")
    print("-" * 50)
    print(f"\nOlder compatibility aliases ({len(LEGACY_TECHNIQUE_REMAPS)} entries)")
    print("-" * 50)
    for old_id, new_id in sorted(LEGACY_TECHNIQUE_REMAPS.items()):
        print(f"  {old_id:<16} -> {new_id:<16}")
    return 0


def cmd_navigator(args: argparse.Namespace) -> int:
    """Generate an ATT&CK Navigator layer with all loaded techniques."""
    from .models import Domain

    index = _load_index()

    domain_map = {
        "enterprise": Domain.ENTERPRISE,
        "mobile": Domain.MOBILE,
        "ics": Domain.ICS,
    }
    domain = domain_map[args.domain]

    # Build a layer with all techniques scored at 0 (no detection data)
    techniques = []
    seen = set()
    for tech_id, tech in index._by_id.items():
        if tech.domain != domain:
            continue
        if tech_id in seen:
            continue
        seen.add(tech_id)
        tactic_ids = tech.tactic_ids
        # Use first tactic for the layer entry
        tactic = tactic_ids[0] if tactic_ids else ""
        techniques.append(
            {
                "techniqueID": tech.attack_id,
                "tactic": tactic,
                "score": 0,
                "comment": "",
                "enabled": True,
                "color": "",
                "metadata": [],
            }
        )

    layer = {
        "name": f"{args.name} ATT&CK v19 Technique Inventory",
        "versions": {"attack": "19", "navigator": "4.9", "layer": "4.5"},
        "domain": f"{args.domain}-attack",
        "description": (
            "Unscored technique inventory generated by attack-v19-core CLI. ATT&CK v19."
        ),
        "filters": {
            "platforms": (
                [
                    "Windows",
                    "macOS",
                    "Linux",
                    "AWS",
                    "Azure",
                    "GCP",
                    "Containers",
                    "Network",
                    "SaaS",
                    "IaaS",
                    "Office 365",
                    "Google Workspace",
                ]
                if args.domain == "enterprise"
                else []
            )
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "max",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Inventory entry", "color": "#ff6666"},
        ],
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "metadata": [
            {"name": "attack_version", "value": "19"},
            {"name": "generated_by", "value": "attack-v19-core"},
            {
                "name": "tactic_note",
                "value": "TA0005=Stealth (renamed from Defense Evasion); TA0112=Defense Impairment (new)",
            },
        ],
    }

    output = json.dumps(layer, indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(f"Navigator layer written to {out_path} ({len(techniques)} techniques)")
    else:
        print(output)

    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "lookup": cmd_lookup,
        "revoked": cmd_revoked,
        "navigator": cmd_navigator,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
