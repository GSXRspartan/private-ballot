#!/usr/bin/env python3
"""Independent valid-vector verifier for the Tari Council private-ballot protocol.

This module intentionally imports only the Python standard library. It does not
import, execute, or bind to any project Rust crate or canonical serialization API.
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

VERIFIER_ID = "python-stdlib-independent-v1"
REPORT_SCHEMA = "tari-cc-private-ballot-independent-verification-v1"
INPUT_SCHEMA = "tari-cc-private-ballot-valid-input-v1"
RESULT_SCHEMA = "tari-cc-private-ballot-valid-result-v1"
HASH_SCHEMA = "tari-cc-private-ballot-valid-hash-v1"
CANONICAL_ENCODING = "deterministic-cbor-rfc8949-4.2.1"
HASH_ALGORITHM_ID = "TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC"
TEST_ONLY_SUITE_ID = "TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS"
HASH_FRAME_PREFIX = b"TARI_CC_PRIVATE_BALLOT_HASH_FRAME_V1"
MASK64 = (1 << 64) - 1
MAX_INPUT_BYTES = 1 << 20
MAX_DEPTH = 64
MAX_PROPOSAL_QUESTION_BYTES = 512

FAMILY_METADATA = {
    "registry-snapshot-v1": (
        "RegistrySnapshot::from_canonical_cbor",
        "tari-cc-private-ballot/registry-snapshot/v1",
    ),
    "candidate-set-v1": (
        "CandidateSet::from_canonical_cbor",
        "tari-cc-private-ballot/candidate-set/v1",
    ),
    "approval-ballot-payload-v1": (
        "ApprovalBallotPayload::from_canonical_cbor",
        "tari-cc-private-ballot/approval-ballot-payload/v1",
    ),
    "election-manifest-v1": (
        "ElectionManifestV1::from_canonical_cbor",
        "tari-cc-private-ballot/election-manifest/v1",
    ),
    "election-manifest-v2": (
        "ElectionManifestV2::from_canonical_cbor",
        "tari-cc-private-ballot/election-manifest/v2",
    ),
    "ballot-package-v1": (
        "BallotPackageV1::from_canonical_cbor",
        "tari-cc-private-ballot/ballot-package/v1",
    ),
    "archive-manifest-v1": (
        "ArchiveManifestV1::from_canonical_cbor",
        "tari-cc-private-ballot/archive-manifest/v1",
    ),
}

REQUIRED_CASE_FILES = {
    "description.md",
    "input.json",
    "canonical.cbor",
    "canonical.hex",
    "expected.json",
    "expected-hashes.json",
}

REQUIRED_INVALID_CASE_FILES = {
    "description.md",
    "input.json",
    "invalid.cbor",
    "invalid.hex",
    "expected.json",
}

REQUIRED_CASE_IDS = {
    "registry-snapshot-multi-member",
    "candidate-set-governance-options",
    "approval-ballot-single-selection",
    "election-manifest-candidate-election",
    "ballot-package-candidate-election",
    "archive-manifest-candidate-election",
    "election-manifest-ballot-measure",
    "election-manifest-v2-candidate-election",
    "election-manifest-v2-ballot-measure",
    "ballot-package-ballot-measure",
    "archive-manifest-ballot-measure",
}

REQUIRED_INVALID_V2_CASE_IDS = {
    "election-manifest-v2-c1-control-question",
    "election-manifest-v2-indefinite-array",
    "election-manifest-v2-leading-whitespace-question",
    "election-manifest-v2-non-nfc-question",
    "election-manifest-v2-wrong-field-count-v1-payload",
}


class VerificationError(ValueError):
    """Raised when a vector or canonical CBOR item fails verification."""


@dataclass(frozen=True)
class CborMap:
    """Map representation preserving canonical encoded-key order."""

    entries: tuple[tuple[Any, Any], ...]


@dataclass(frozen=True)
class CaseResult:
    vector_id: str
    object_family: str
    canonical_byte_length: int
    domain_label: str
    digest_hex: str
    decision_type: str | None

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "vector_id": self.vector_id,
            "object_family": self.object_family,
            "canonical_byte_length": self.canonical_byte_length,
            "domain_label": self.domain_label,
            "digest_hex": self.digest_hex,
            "round_trip_equal": True,
        }
        if self.decision_type is not None:
            result["decision_type"] = self.decision_type
        return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"unable to parse JSON {path}: {error}") from error

    _require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value


def _require_property(
    value: dict[str, Any],
    property_name: str,
    expected_type: type | tuple[type, ...],
    source: Path,
) -> Any:
    _require(
        property_name in value,
        f"required property {property_name!r} is missing: {source}",
    )
    result = value[property_name]

    if expected_type is int:
        _require(
            _is_exact_int(result),
            f"property {property_name!r} must be an integer: {source}",
        )
    elif expected_type is bool:
        _require(
            isinstance(result, bool),
            f"property {property_name!r} must be a boolean: {source}",
        )
    else:
        _require(
            isinstance(result, expected_type),
            f"property {property_name!r} has an unexpected type: {source}",
        )

    return result


def _encode_argument(major: int, value: int) -> bytes:
    _require(0 <= major <= 7, "CBOR major type is out of range")
    _require(0 <= value <= MASK64, "CBOR argument is out of the u64 range")

    prefix = major << 5
    if value <= 23:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + value.to_bytes(4, "big")
    return bytes((prefix | 27,)) + value.to_bytes(8, "big")


def encode_canonical(value: Any) -> bytes:
    """Encodes the supported deterministic CBOR subset independently."""

    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"

    if _is_exact_int(value):
        _require(value >= 0, "negative integers are outside the implemented V1 subset")
        return _encode_argument(0, value)

    if isinstance(value, bytes):
        return _encode_argument(2, len(value)) + value

    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _encode_argument(3, len(encoded)) + encoded

    if isinstance(value, list):
        return _encode_argument(4, len(value)) + b"".join(
            encode_canonical(item) for item in value
        )

    if isinstance(value, CborMap):
        encoded_entries: list[tuple[bytes, bytes]] = []
        previous_order_key: tuple[int, bytes] | None = None
        seen_keys: set[bytes] = set()

        for key, item in value.entries:
            encoded_key = encode_canonical(key)
            encoded_value = encode_canonical(item)
            order_key = (len(encoded_key), encoded_key)

            _require(encoded_key not in seen_keys, "duplicate canonical CBOR map key")
            if previous_order_key is not None:
                _require(
                    previous_order_key < order_key,
                    "CBOR map keys are not in deterministic encoded-key order",
                )

            seen_keys.add(encoded_key)
            previous_order_key = order_key
            encoded_entries.append((encoded_key, encoded_value))

        return _encode_argument(5, len(encoded_entries)) + b"".join(
            key + item for key, item in encoded_entries
        )

    raise VerificationError(f"unsupported CBOR value type: {type(value).__name__}")


class CanonicalCborDecoder:
    """Strict decoder for the current deterministic CBOR profile."""

    def __init__(self, encoded: bytes) -> None:
        _require(len(encoded) <= MAX_INPUT_BYTES, "CBOR input exceeds verifier limit")
        self._encoded = encoded
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    def decode_complete(self) -> Any:
        value = self._decode_value(0)
        _require(
            self._offset == len(self._encoded),
            "trailing bytes remain after the canonical CBOR item",
        )
        return value

    def _read(self, length: int) -> bytes:
        _require(length >= 0, "negative read length")
        end = self._offset + length
        _require(end <= len(self._encoded), "truncated CBOR input")
        result = self._encoded[self._offset:end]
        self._offset = end
        return result

    def _read_byte(self) -> int:
        return self._read(1)[0]

    def _read_argument(self, additional: int) -> int:
        if additional <= 23:
            return additional

        if additional == 24:
            value = self._read_byte()
            _require(value >= 24, "CBOR argument does not use its shortest encoding")
            return value

        if additional == 25:
            value = int.from_bytes(self._read(2), "big")
            _require(value > 0xFF, "CBOR argument does not use its shortest encoding")
            return value

        if additional == 26:
            value = int.from_bytes(self._read(4), "big")
            _require(value > 0xFFFF, "CBOR argument does not use its shortest encoding")
            return value

        if additional == 27:
            value = int.from_bytes(self._read(8), "big")
            _require(value > 0xFFFFFFFF, "CBOR argument does not use its shortest encoding")
            return value

        if additional == 31:
            raise VerificationError("indefinite-length CBOR items are not permitted")

        raise VerificationError("reserved CBOR additional information")

    def _decode_value(self, depth: int) -> Any:
        _require(depth <= MAX_DEPTH, "CBOR nesting exceeds verifier limit")

        initial = self._read_byte()
        major = initial >> 5
        additional = initial & 0x1F

        if major == 0:
            return self._read_argument(additional)

        if major == 2:
            length = self._read_argument(additional)
            return self._read(length)

        if major == 3:
            length = self._read_argument(additional)
            raw = self._read(length)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise VerificationError("CBOR text string is not valid UTF-8") from error

        if major == 4:
            length = self._read_argument(additional)
            return [self._decode_value(depth + 1) for _ in range(length)]

        if major == 5:
            length = self._read_argument(additional)
            entries: list[tuple[Any, Any]] = []
            previous_order_key: tuple[int, bytes] | None = None
            seen_keys: set[bytes] = set()

            for _ in range(length):
                key_start = self._offset
                key = self._decode_value(depth + 1)
                encoded_key = self._encoded[key_start:self._offset]
                order_key = (len(encoded_key), encoded_key)

                _require(encoded_key not in seen_keys, "duplicate canonical CBOR map key")
                if previous_order_key is not None:
                    _require(
                        previous_order_key < order_key,
                        "CBOR map keys are not in deterministic encoded-key order",
                    )

                value = self._decode_value(depth + 1)
                entries.append((key, value))
                seen_keys.add(encoded_key)
                previous_order_key = order_key

            return CborMap(tuple(entries))

        if major == 7 and additional in (20, 21):
            return additional == 21

        if major == 1:
            raise VerificationError(
                "negative integers are outside the implemented V1 subset"
            )

        raise VerificationError(f"unsupported CBOR major type {major}")


def decode_canonical(encoded: bytes) -> Any:
    return CanonicalCborDecoder(encoded).decode_complete()


def _rotate_left_u64(value: int, count: int) -> int:
    count %= 64
    value &= MASK64
    if count == 0:
        return value
    return ((value << count) | (value >> (64 - count))) & MASK64


def _rotate_left_u8(value: int, count: int) -> int:
    count %= 8
    value &= 0xFF
    if count == 0:
        return value
    return ((value << count) | (value >> (8 - count))) & 0xFF


def test_only_hash(framed_input: bytes) -> bytes:
    """Reproduces the explicit non-cryptographic Rust test provider."""

    output = bytearray(32)
    state = 0x9E3779B97F4A7C15

    for index, byte in enumerate(framed_input):
        lane = index % len(output)
        shift = (lane % 8) * 8

        mixed = _rotate_left_u64((byte + index) & MASK64, index % 64)
        state ^= mixed
        state = (_rotate_left_u64(state, 13) * 0x00000100000001B3) & MASK64

        output[lane] = (
            output[lane]
            + ((state >> shift) & 0xFF)
            + _rotate_left_u8(byte, lane % 8)
        ) & 0xFF

    for lane in range(len(output)):
        state ^= (lane * 0x9E3779B97F4A7C15) & MASK64
        state = (_rotate_left_u64(state, 17) * 0x94D049BB133111EB) & MASK64
        shift = (lane % 8) * 8
        output[lane] ^= (state >> shift) & 0xFF

    return bytes(output)


def domain_separated_hash(domain_label: str, canonical: bytes) -> bytes:
    framed = (
        HASH_FRAME_PREFIX
        + b"\x00"
        + domain_label.encode("ascii")
        + b"\x00"
        + canonical
    )
    return test_only_hash(framed)


def _strictly_increasing(values: Sequence[bytes | str], description: str) -> None:
    for previous, current in zip(values, values[1:]):
        _require(previous < current, f"{description} are not strictly ordered")


def _validate_registry(value: Any) -> None:
    _require(isinstance(value, list) and value, "registry must be a non-empty array")
    _require(all(isinstance(item, bytes) and item for item in value), "invalid registry key")
    _strictly_increasing(value, "registry keys")


def _validate_candidate_set(value: Any) -> None:
    _require(isinstance(value, list) and value, "candidate set must be a non-empty array")
    identifiers: list[bytes] = []

    for entry in value:
        _require(isinstance(entry, list) and len(entry) == 2, "invalid candidate entry")
        identifier, display_name = entry
        _require(isinstance(identifier, bytes) and identifier, "invalid candidate identifier")
        _require(
            isinstance(display_name, str) and bool(display_name.strip()),
            "invalid candidate display name",
        )
        identifiers.append(identifier)

    _strictly_increasing(identifiers, "candidate identifiers")


def _validate_approval_payload(value: Any) -> None:
    _require(isinstance(value, list), "approval payload must be an array")
    _require(
        all(isinstance(item, bytes) and item for item in value),
        "invalid approval selection",
    )
    _strictly_increasing(value, "approval selections")


def _validate_election_manifest_common(value: Any, field_count: int) -> None:
    _require(
        isinstance(value, list) and len(value) == field_count,
        "invalid election manifest shape",
    )
    _require(_is_exact_int(value[0]) and value[0] == 1, "invalid manifest protocol version")
    _require(isinstance(value[1], bytes) and value[1], "invalid election identifier")
    _require(value[2] == "NON_BINDING_APPROVAL_PILOT", "unexpected ballot kind")
    _require(value[3] == "PUBLIC", "unexpected ballot confidentiality")
    _require(isinstance(value[4], bytes) and len(value[4]) == 32, "invalid registry commitment")
    _require(
        isinstance(value[5], bytes) and len(value[5]) == 32,
        "invalid candidate-set commitment",
    )
    _require(value[6] == TEST_ONLY_SUITE_ID, "unexpected proof-suite identifier")

    limits = value[7]
    _require(isinstance(limits, list) and len(limits) == 3, "invalid approval limits")
    minimum, maximum, allow_abstention = limits
    _require(_is_exact_int(minimum) and minimum >= 0, "invalid minimum approval count")
    _require(_is_exact_int(maximum) and maximum >= minimum, "invalid maximum approval count")
    _require(isinstance(allow_abstention, bool), "invalid abstention flag")
    _require(
        isinstance(value[8], str) and bool(value[8].strip()),
        "invalid governance-source revision",
    )


def _is_forbidden_control(character: str) -> bool:
    codepoint = ord(character)
    return codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F


def _validate_proposal_question(value: Any) -> None:
    _require(isinstance(value, str), "invalid proposal question")
    _require(value != "" and bool(value.strip()), "empty proposal question")
    _require(
        len(value.encode("utf-8")) <= MAX_PROPOSAL_QUESTION_BYTES,
        "proposal question exceeds the protocol size limit",
    )
    _require(not value[0].isspace(), "proposal question starts with whitespace")
    _require(not value[-1].isspace(), "proposal question ends with whitespace")
    _require("\n" not in value and "\r" not in value, "proposal question contains newline")
    _require(
        all(not _is_forbidden_control(character) for character in value),
        "proposal question contains a forbidden control",
    )
    _require(
        unicodedata.normalize("NFC", value) == value,
        "proposal question is not NFC",
    )


def _validate_election_manifest_v1(value: Any) -> None:
    _validate_election_manifest_common(value, 9)


def _validate_election_manifest_v2(value: Any) -> None:
    _validate_election_manifest_common(value, 10)
    _validate_proposal_question(value[9])


def _validate_ballot_package(value: Any) -> None:
    _require(isinstance(value, list) and len(value) == 5, "invalid ballot package shape")
    _require(_is_exact_int(value[0]) and value[0] == 1, "invalid package protocol version")
    _require(isinstance(value[1], bytes) and len(value[1]) == 32, "invalid manifest hash")
    _require(value[2] == TEST_ONLY_SUITE_ID, "unexpected package proof suite")
    _require(isinstance(value[3], bytes), "ballot payload must be embedded CBOR bytes")
    _require(isinstance(value[4], bytes), "proof must be a byte string")
    _require(value[4].startswith(TEST_ONLY_SUITE_ID.encode("ascii")), "missing test-only proof marker")

    nested_payload = decode_canonical(value[3])
    _validate_approval_payload(nested_payload)
    _require(
        encode_canonical(nested_payload) == value[3],
        "embedded approval payload does not round-trip canonically",
    )


def _validate_archive_manifest(value: Any) -> None:
    _require(isinstance(value, list) and len(value) == 4, "invalid archive manifest shape")
    _require(_is_exact_int(value[0]) and value[0] == 1, "invalid archive-manifest version")
    _require(
        isinstance(value[1], bytes) and len(value[1]) == 32,
        "invalid election-manifest hash",
    )
    _require(value[2] == HASH_ALGORITHM_ID, "unexpected archive hash algorithm")
    _require(isinstance(value[3], list) and value[3], "archive file catalog must be non-empty")

    paths: list[str] = []
    portable_paths: set[str] = set()

    for entry in value[3]:
        _require(isinstance(entry, list) and len(entry) == 2, "invalid archive file entry")
        path, digest = entry
        _require(isinstance(path, str) and path, "invalid archive path")
        _require(isinstance(digest, bytes) and len(digest) == 32, "invalid archive digest")
        _validate_archive_path(path)
        portable = path.lower()
        _require(portable not in portable_paths, "duplicate or case-colliding archive path")
        portable_paths.add(portable)
        paths.append(path)

    _strictly_increasing(paths, "archive paths")


def _validate_archive_path(path: str) -> None:
    _require(path.isascii(), "archive path must be ASCII")
    _require(not path.startswith("/") and not path.endswith("/"), "archive path must be relative")
    _require("\\" not in path and ":" not in path, "archive path contains a forbidden separator")
    _require(
        all(character.isalnum() or character in "-_./" for character in path),
        "archive path contains a forbidden character",
    )

    reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }

    for segment in path.split("/"):
        _require(segment not in ("", ".", ".."), "archive path contains traversal")
        _require(not segment.endswith("."), "archive path segment ends with a dot")
        stem = segment.split(".", 1)[0].upper()
        _require(stem not in reserved, "archive path contains a reserved device name")


FAMILY_VALIDATORS = {
    "registry-snapshot-v1": _validate_registry,
    "candidate-set-v1": _validate_candidate_set,
    "approval-ballot-payload-v1": _validate_approval_payload,
    "election-manifest-v1": _validate_election_manifest_v1,
    "election-manifest-v2": _validate_election_manifest_v2,
    "ballot-package-v1": _validate_ballot_package,
    "archive-manifest-v1": _validate_archive_manifest,
}


def verify_case(case_dir: Path) -> CaseResult:
    actual_files = {path.name for path in case_dir.iterdir() if path.is_file()}
    _require(
        actual_files == REQUIRED_CASE_FILES,
        f"unexpected file layout for {case_dir.name}: {sorted(actual_files)}",
    )

    input_path = case_dir / "input.json"
    expected_path = case_dir / "expected.json"
    hashes_path = case_dir / "expected-hashes.json"

    input_json = _read_json_object(input_path)
    expected_json = _read_json_object(expected_path)
    hashes_json = _read_json_object(hashes_path)

    _require(
        _require_property(input_json, "schema", str, input_path) == INPUT_SCHEMA,
        f"unexpected input schema: {case_dir.name}",
    )
    vector_id = _require_property(input_json, "vector_id", str, input_path)
    _require(vector_id == case_dir.name, f"vector identifier differs from directory: {case_dir.name}")

    object_family = _require_property(input_json, "object_family", str, input_path)
    _require(object_family in FAMILY_METADATA, f"unsupported object family: {object_family}")
    decoder_target, expected_domain = FAMILY_METADATA[object_family]

    _require(
        _require_property(expected_json, "schema", str, expected_path) == RESULT_SCHEMA,
        f"unexpected result schema: {case_dir.name}",
    )
    _require(
        _require_property(expected_json, "vector_id", str, expected_path) == vector_id,
        f"result vector identifier mismatch: {case_dir.name}",
    )
    _require(
        _require_property(expected_json, "accepted", bool, expected_path) is True,
        f"valid vector is not marked accepted: {case_dir.name}",
    )
    _require(
        _require_property(expected_json, "decoder_target", str, expected_path) == decoder_target,
        f"decoder target mismatch: {case_dir.name}",
    )
    _require(
        _require_property(expected_json, "canonical_encoding", str, expected_path)
        == CANONICAL_ENCODING,
        f"canonical profile mismatch: {case_dir.name}",
    )

    canonical = (case_dir / "canonical.cbor").read_bytes()
    _require(bool(canonical), f"canonical bytes are empty: {case_dir.name}")
    _require(
        _require_property(expected_json, "canonical_byte_length", int, expected_path)
        == len(canonical),
        f"canonical byte length mismatch: {case_dir.name}",
    )

    published_hex = (case_dir / "canonical.hex").read_text(encoding="ascii").strip()
    _require(published_hex == canonical.hex(), f"hex rendering mismatch: {case_dir.name}")
    _require(
        published_hex == published_hex.lower(),
        f"hex rendering is not lowercase: {case_dir.name}",
    )

    parsed = decode_canonical(canonical)
    FAMILY_VALIDATORS[object_family](parsed)
    _require(
        encode_canonical(parsed) == canonical,
        f"independent decode/re-encode mismatch: {case_dir.name}",
    )

    _require(
        _require_property(hashes_json, "schema", str, hashes_path) == HASH_SCHEMA,
        f"unexpected hash schema: {case_dir.name}",
    )
    _require(
        _require_property(hashes_json, "vector_id", str, hashes_path) == vector_id,
        f"hash vector identifier mismatch: {case_dir.name}",
    )
    _require(
        _require_property(hashes_json, "hash_algorithm_id", str, hashes_path)
        == HASH_ALGORITHM_ID,
        f"hash provider mismatch: {case_dir.name}",
    )
    domain_label = _require_property(hashes_json, "domain_label", str, hashes_path)
    _require(domain_label == expected_domain, f"hash domain mismatch: {case_dir.name}")

    digest_hex = _require_property(hashes_json, "digest_hex", str, hashes_path)
    _require(len(digest_hex) == 64, f"digest length mismatch: {case_dir.name}")
    _require(digest_hex == digest_hex.lower(), f"digest is not lowercase: {case_dir.name}")
    try:
        bytes.fromhex(digest_hex)
    except ValueError as error:
        raise VerificationError(f"digest is not hexadecimal: {case_dir.name}") from error

    independent_digest = domain_separated_hash(domain_label, canonical).hex()
    _require(
        independent_digest == digest_hex,
        f"cross-implementation digest mismatch: {case_dir.name}",
    )

    decision_type: str | None = None
    if "decision_type" in input_json:
        decision_type = _require_property(input_json, "decision_type", str, input_path)
        _require(
            decision_type in {"candidate-election", "ballot-measure"},
            f"unsupported decision type: {case_dir.name}",
        )
        _require(
            _require_property(expected_json, "decision_type", str, expected_path)
            == decision_type,
            f"result decision type mismatch: {case_dir.name}",
        )
        _require(
            _require_property(hashes_json, "decision_type", str, hashes_path)
            == decision_type,
            f"hash decision type mismatch: {case_dir.name}",
        )

    return CaseResult(
        vector_id=vector_id,
        object_family=object_family,
        canonical_byte_length=len(canonical),
        domain_label=domain_label,
        digest_hex=digest_hex,
        decision_type=decision_type,
    )


def build_report(results: Sequence[CaseResult]) -> dict[str, Any]:
    ordered = sorted(results, key=lambda item: item.vector_id)
    object_families = sorted({item.object_family for item in ordered})
    decision_types = sorted(
        {item.decision_type for item in ordered if item.decision_type is not None}
    )

    return {
        "schema": REPORT_SCHEMA,
        "verifier_id": VERIFIER_ID,
        "implementation_language": "python-standard-library",
        "project_canonical_api_imports": False,
        "hash_algorithm_id": HASH_ALGORITHM_ID,
        "case_count": len(ordered),
        "object_families": object_families,
        "decision_types": decision_types,
        "all_canonical_hex_equal": True,
        "all_decode_reencode_equal": True,
        "all_domain_hashes_equal": True,
        "cases": [item.to_json() for item in ordered],
        "warning": (
            "The proof and hash providers are deterministic, forgeable, "
            "non-anonymous test plumbing and are not suitable for binding elections."
        ),
    }


def report_bytes(report: dict[str, Any]) -> bytes:
    return (
        json.dumps(report, indent=2, ensure_ascii=True, sort_keys=False) + "\n"
    ).encode("utf-8")


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve()
    verify_invalid_v2_repository(root)

    vector_root = root / "test-vectors" / "valid" / "canonical-v1"
    _require(vector_root.is_dir(), f"valid-vector root does not exist: {vector_root}")

    case_dirs = sorted(path for path in vector_root.iterdir() if path.is_dir())
    _require(case_dirs, "no valid-vector case directories were found")

    actual_ids = {path.name for path in case_dirs}
    missing_ids = sorted(REQUIRED_CASE_IDS - actual_ids)
    _require(not missing_ids, f"required valid vectors are missing: {missing_ids}")

    results = [verify_case(case_dir) for case_dir in case_dirs]
    report = build_report(results)

    _require(report["case_count"] >= len(REQUIRED_CASE_IDS), "verified case count is too small")
    _require(
        set(report["object_families"]) == set(FAMILY_METADATA),
        "implemented object-family coverage is incomplete",
    )
    _require(
        set(report["decision_types"]) == {"candidate-election", "ballot-measure"},
        "candidate-election and ballot-measure coverage is incomplete",
    )

    return report


def _classify_invalid_v2_rejection(error: VerificationError) -> str:
    message = str(error)

    if "indefinite-length" in message or "shortest encoding" in message:
        return "NON_CANONICAL_CBOR"
    if "not NFC" in message:
        return "NON_NFC_PROPOSAL_QUESTION"
    if "empty proposal question" in message:
        return "EMPTY_PROPOSAL_QUESTION"
    if "size limit" in message:
        return "PROTOCOL_LIMIT_EXCEEDED"
    if (
        "invalid proposal question" in message
        or "starts with whitespace" in message
        or "ends with whitespace" in message
        or "contains newline" in message
        or "forbidden control" in message
    ):
        return "INVALID_PROPOSAL_QUESTION"
    return "INVALID_CBOR"


def verify_invalid_v2_case(case_dir: Path) -> dict[str, str]:
    missing_files = sorted(REQUIRED_INVALID_CASE_FILES - {path.name for path in case_dir.iterdir()})
    _require(not missing_files, f"invalid-vector case is missing files {missing_files}: {case_dir}")

    input_metadata = _read_json_object(case_dir / "input.json")
    expected = _read_json_object(case_dir / "expected.json")
    vector_id = _require_property(input_metadata, "vector_id", str, case_dir / "input.json")
    target = _require_property(input_metadata, "target", str, case_dir / "input.json")
    byte_length = _require_property(input_metadata, "byte_length", int, case_dir / "input.json")
    expected_vector_id = _require_property(expected, "vector_id", str, case_dir / "expected.json")
    expected_target = _require_property(expected, "target", str, case_dir / "expected.json")
    accepted = _require_property(expected, "accepted", bool, case_dir / "expected.json")
    expected_code = _require_property(
        expected,
        "expected_rejection_code",
        str,
        case_dir / "expected.json",
    )

    _require(vector_id == case_dir.name, f"invalid vector_id must match directory: {case_dir}")
    _require(vector_id == expected_vector_id, f"expected vector_id mismatch: {case_dir}")
    _require(target == expected_target, f"target mismatch: {case_dir}")
    _require(target == FAMILY_METADATA["election-manifest-v2"][0], f"unsupported invalid target: {case_dir}")
    _require(not accepted, f"invalid vector expected accepted=false: {case_dir}")

    invalid_bytes = (case_dir / "invalid.cbor").read_bytes()
    invalid_hex = (case_dir / "invalid.hex").read_text(encoding="ascii").strip()
    _require(len(invalid_bytes) == byte_length, f"invalid byte_length mismatch: {case_dir}")
    _require(invalid_bytes.hex() == invalid_hex, f"invalid hex does not match bytes: {case_dir}")

    try:
        decoded = decode_canonical(invalid_bytes)
        _validate_election_manifest_v2(decoded)
    except VerificationError as error:
        actual_code = _classify_invalid_v2_rejection(error)
    else:
        raise VerificationError(f"invalid V2 manifest vector was accepted: {case_dir}")

    _require(
        actual_code == expected_code,
        f"invalid V2 rejection mismatch for {case_dir}: expected {expected_code}, got {actual_code}",
    )

    return {
        "vector_id": vector_id,
        "target": target,
        "expected_rejection_code": expected_code,
    }


def verify_invalid_v2_repository(root: Path) -> list[dict[str, str]]:
    invalid_root = root / "test-vectors" / "invalid" / "cbor-v1"
    _require(invalid_root.is_dir(), f"invalid-vector root does not exist: {invalid_root}")

    missing_ids = sorted(
        vector_id
        for vector_id in REQUIRED_INVALID_V2_CASE_IDS
        if not (invalid_root / vector_id).is_dir()
    )
    _require(not missing_ids, f"required invalid V2 vectors are missing: {missing_ids}")

    return [
        verify_invalid_v2_case(invalid_root / vector_id)
        for vector_id in sorted(REQUIRED_INVALID_V2_CASE_IDS)
    ]


def _print_summary(report: dict[str, Any]) -> None:
    print("Independent canonical-vector verification passed.")
    print(f"Verifier: {report['verifier_id']}")
    print(f"Cases verified: {report['case_count']}")
    print(f"Object families: {len(report['object_families'])}")
    print("Decision types: " + ", ".join(report["decision_types"]))
    print("Canonical decode/re-encode agreement: yes")
    print("Domain-separated hash agreement: yes")
    print(f"WARNING: {report['warning']}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently verify checked-in canonical ballot vectors."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root containing test-vectors (default: current directory)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="write a deterministic JSON verification report",
    )
    parser.add_argument(
        "--check-report",
        type=Path,
        help="require an existing report to equal newly calculated results",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)

    try:
        report = verify_repository(arguments.root)
        encoded_report = report_bytes(report)

        if arguments.check_report is not None:
            existing = arguments.check_report.read_bytes()
            _require(
                existing == encoded_report,
                f"verification report differs: {arguments.check_report}",
            )

        if arguments.report is not None:
            arguments.report.parent.mkdir(parents=True, exist_ok=True)
            arguments.report.write_bytes(encoded_report)

        _print_summary(report)
        return 0
    except (OSError, VerificationError) as error:
        print(f"Independent canonical-vector verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
