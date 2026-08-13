#!/usr/bin/env python3
"""Tests for the independent standard-library vector verifier."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("independent_vector_verifier.py")
SPEC = importlib.util.spec_from_file_location("independent_vector_verifier", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load verifier module: {MODULE_PATH}")

verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class CanonicalCborTests(unittest.TestCase):
    def test_unsigned_integer_boundaries_round_trip(self) -> None:
        values = [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            (1 << 32) - 1,
            1 << 32,
            (1 << 64) - 1,
        ]

        for value in values:
            with self.subTest(value=value):
                encoded = verifier.encode_canonical(value)
                self.assertEqual(verifier.decode_canonical(encoded), value)
                self.assertEqual(verifier.encode_canonical(verifier.decode_canonical(encoded)), encoded)

    def test_compound_vector_matches_protocol_example(self) -> None:
        value = verifier.CborMap(
            (
                ("a", 1),
                ("b", [True, False, b"\xaa\xbb"]),
            )
        )
        expected = bytes.fromhex("a2616101616283f5f442aabb")

        self.assertEqual(verifier.encode_canonical(value), expected)
        self.assertEqual(verifier.decode_canonical(expected), value)

    def test_non_shortest_unsigned_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "shortest"):
            verifier.decode_canonical(bytes((0x18, 0x17)))

    def test_indefinite_array_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "indefinite"):
            verifier.decode_canonical(bytes((0x9F,)))

    def test_trailing_data_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "trailing"):
            verifier.decode_canonical(bytes((0x01, 0x02)))

    def test_invalid_utf8_is_rejected(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "UTF-8"):
            verifier.decode_canonical(bytes((0x61, 0xFF)))


class TestOnlyHashTests(unittest.TestCase):
    def test_stable_raw_hash_vector(self) -> None:
        self.assertEqual(
            verifier.test_only_hash(b"abc").hex(),
            "2722d74de794f391c7e308df46ef50d9d19a916e5007a735939021e9d915b542",
        )

    def test_stable_domain_separated_vector(self) -> None:
        self.assertEqual(
            verifier.domain_separated_hash(
                "tari-cc-private-ballot/election-manifest/v1",
                bytes((1, 2, 3)),
            ).hex(),
            "e1d6c66279ae9807d8119cdc006c4d4b01f2afca6f483c7e0ebb1b856486b612",
        )

    def test_stable_v2_manifest_domain_separated_vector(self) -> None:
        self.assertEqual(
            verifier.domain_separated_hash(
                "tari-cc-private-ballot/election-manifest/v2",
                bytes((1, 2, 3)),
            ).hex(),
            "cdb4a141517b49f6127cc5622e4ed436ad125f9805cf79c3c9f43ebd7ad385e4",
        )


class ElectionManifestV2ValidationTests(unittest.TestCase):
    def manifest(self, question: str) -> list[object]:
        return [
            1,
            b"election",
            "NON_BINDING_APPROVAL_PILOT",
            "PUBLIC",
            bytes([1]) * 32,
            bytes([2]) * 32,
            verifier.TEST_ONLY_SUITE_ID,
            [1, 1, True],
            "revision-1",
            question,
        ]

    def test_valid_v2_question_is_accepted_exactly(self) -> None:
        verifier._validate_election_manifest_v2(
            self.manifest("Should the council adopt RFC-0185?")
        )

    def test_v2_question_rejects_empty_and_whitespace_only_text(self) -> None:
        for question in ["", "   "]:
            with self.subTest(question=repr(question)):
                with self.assertRaisesRegex(verifier.VerificationError, "empty"):
                    verifier._validate_election_manifest_v2(self.manifest(question))

    def test_v2_question_rejects_non_nfc_text(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "NFC"):
            verifier._validate_election_manifest_v2(self.manifest("Cafe\u0301?"))

    def test_v2_question_rejects_leading_whitespace(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "starts with whitespace"):
            verifier._validate_election_manifest_v2(self.manifest(" Question?"))

    def test_v2_question_rejects_trailing_whitespace(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "ends with whitespace"):
            verifier._validate_election_manifest_v2(self.manifest("Question? "))

    def test_v2_question_rejects_embedded_newline(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "newline"):
            verifier._validate_election_manifest_v2(self.manifest("Question?\nYes"))

    def test_v2_question_rejects_controls(self) -> None:
        for question in ["Question?\x00 Yes", "Question?\x7f Yes", "Question?\u0085 Yes"]:
            with self.subTest(question=repr(question)):
                with self.assertRaisesRegex(verifier.VerificationError, "forbidden control"):
                    verifier._validate_election_manifest_v2(self.manifest(question))

    def test_v2_question_rejects_oversized_utf8(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "size limit"):
            verifier._validate_election_manifest_v2(
                self.manifest("q" * (verifier.MAX_PROPOSAL_QUESTION_BYTES + 1))
            )

    def test_v2_shape_is_strict(self) -> None:
        v2 = self.manifest("Question?")
        v1 = v2[:-1]
        with self.assertRaisesRegex(verifier.VerificationError, "shape"):
            verifier._validate_election_manifest_v2(v1)
        with self.assertRaisesRegex(verifier.VerificationError, "shape"):
            verifier._validate_election_manifest_v1(v2)

    def test_one_byte_question_mutation_changes_v2_digest(self) -> None:
        first = verifier.encode_canonical(self.manifest("Question A?"))
        second = verifier.encode_canonical(self.manifest("Question B?"))
        domain = verifier.FAMILY_METADATA["election-manifest-v2"][1]

        self.assertNotEqual(first, second)
        self.assertNotEqual(
            verifier.domain_separated_hash(domain, first),
            verifier.domain_separated_hash(domain, second),
        )


class FixtureVerificationTests(unittest.TestCase):
    def test_minimal_registry_fixture_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "registry-example"
            case_dir.mkdir()

            canonical = verifier.encode_canonical([b"a"])
            domain = verifier.FAMILY_METADATA["registry-snapshot-v1"][1]
            digest = verifier.domain_separated_hash(domain, canonical).hex()

            (case_dir / "description.md").write_text(
                "# registry-example\n", encoding="utf-8", newline="\n"
            )
            (case_dir / "canonical.cbor").write_bytes(canonical)
            (case_dir / "canonical.hex").write_text(
                canonical.hex() + "\n", encoding="ascii", newline="\n"
            )
            (case_dir / "input.json").write_text(
                json.dumps(
                    {
                        "schema": verifier.INPUT_SCHEMA,
                        "vector_id": "registry-example",
                        "object_family": "registry-snapshot-v1",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (case_dir / "expected.json").write_text(
                json.dumps(
                    {
                        "schema": verifier.RESULT_SCHEMA,
                        "vector_id": "registry-example",
                        "accepted": True,
                        "decoder_target": verifier.FAMILY_METADATA[
                            "registry-snapshot-v1"
                        ][0],
                        "canonical_byte_length": len(canonical),
                        "canonical_encoding": verifier.CANONICAL_ENCODING,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (case_dir / "expected-hashes.json").write_text(
                json.dumps(
                    {
                        "schema": verifier.HASH_SCHEMA,
                        "vector_id": "registry-example",
                        "hash_algorithm_id": verifier.HASH_ALGORITHM_ID,
                        "domain_label": domain,
                        "digest_hex": digest,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )

            result = verifier.verify_case(case_dir)

            self.assertEqual(result.vector_id, "registry-example")
            self.assertEqual(result.object_family, "registry-snapshot-v1")
            self.assertEqual(result.digest_hex, digest)

    def test_checked_in_repository_vectors_verify(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        report = verifier.verify_repository(repository_root)

        self.assertGreaterEqual(report["case_count"], 9)
        self.assertEqual(
            set(report["object_families"]),
            set(verifier.FAMILY_METADATA),
        )
        self.assertEqual(
            set(report["decision_types"]),
            {"candidate-election", "ballot-measure"},
        )

    def test_checked_in_invalid_v2_manifest_vectors_are_rejected(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        results = verifier.verify_invalid_v2_repository(repository_root)

        self.assertEqual(
            {item["vector_id"] for item in results},
            verifier.REQUIRED_INVALID_V2_CASE_IDS,
        )
        self.assertEqual(
            {item["expected_rejection_code"] for item in results},
            {
                "INVALID_CBOR",
                "INVALID_PROPOSAL_QUESTION",
                "NON_CANONICAL_CBOR",
                "NON_NFC_PROPOSAL_QUESTION",
            },
        )


if __name__ == "__main__":
    unittest.main()
