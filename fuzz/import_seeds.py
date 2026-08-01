#!/usr/bin/env python3
"""Import checked-in valid and hostile CBOR vectors into local fuzz corpora."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

TARGET_CASES: dict[str, tuple[str, ...]] = {
    "canonical_cbor_reader": (
        "approval-ballot-single-selection",
        "archive-manifest-ballot-measure",
        "archive-manifest-candidate-election",
        "ballot-package-ballot-measure",
        "ballot-package-candidate-election",
        "candidate-set-governance-options",
        "election-manifest-ballot-measure",
        "election-manifest-candidate-election",
        "registry-snapshot-multi-member",
    ),
    "registry_snapshot": ("registry-snapshot-multi-member",),
    "candidate_set": ("candidate-set-governance-options",),
    "approval_ballot_payload": ("approval-ballot-single-selection",),
    "election_manifest": (
        "election-manifest-ballot-measure",
        "election-manifest-candidate-election",
    ),
    "ballot_package": (
        "ballot-package-ballot-measure",
        "ballot-package-candidate-election",
    ),
    "archive_manifest": (
        "archive-manifest-ballot-measure",
        "archive-manifest-candidate-election",
    ),
}


def copy_seed(source: Path, destination: Path, label: str) -> None:
    payload = source.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()[:16]
    target = destination / f"{label}-{digest}.cbor"
    target.write_bytes(payload)


def import_seeds(root: Path) -> dict[str, int]:
    valid_root = root / "test-vectors" / "valid" / "canonical-v1"
    invalid_root = root / "test-vectors" / "invalid" / "cbor-v1"
    corpus_root = root / "fuzz" / "corpus"

    invalid_cases = sorted(invalid_root.glob("*/invalid.cbor"))
    counts: dict[str, int] = {}

    for target, valid_cases in TARGET_CASES.items():
        destination = corpus_root / target
        destination.mkdir(parents=True, exist_ok=True)

        for existing in destination.glob("seed-*.cbor"):
            existing.unlink()

        for case in valid_cases:
            source = valid_root / case / "canonical.cbor"

            if not source.is_file():
                raise FileNotFoundError(source)

            copy_seed(source, destination, f"seed-valid-{case}")

        for source in invalid_cases:
            copy_seed(
                source,
                destination,
                f"seed-invalid-{source.parent.name}",
            )

        empty_seed = destination / "seed-empty"
        empty_seed.write_bytes(b"")

        counts[target] = len(
            [
                path
                for path in destination.iterdir()
                if path.is_file() and path.name.startswith("seed-")
            ]
        )

    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    arguments = parser.parse_args()

    root = arguments.root.resolve()
    counts = import_seeds(root)

    for target in sorted(counts):
        print(f"{target}: {counts[target]} deterministic seeds")

    print(f"target_count={len(counts)}")
    print(f"total_seed_count={sum(counts.values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
