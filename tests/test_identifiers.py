# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Identifier primitives: UIDs, AHVN13, CHE UID, GTIN, SPID."""

from __future__ import annotations

import pytest

from ehealth.domain.uid import (
    SPID_LENGTH,
    Ahvn13,
    CheUid,
    IdentifierError,
    Uid,
    format_spid,
    is_valid_atc,
    is_valid_gln,
    is_valid_gtin,
    is_valid_pharmacode,
    is_valid_spid,
    is_valid_swissmedic_authorisation,
    is_valid_veka,
    is_valid_zsr,
    new_ulid,
    normalise_swissmedic_authorisation,
    normalise_zsr,
    spid_from_entropy,
    ulid_timestamp_ms,
)


class TestUlid:
    def test_is_26_characters_and_sorts_by_time(self):
        early = new_ulid(now_ms=1_000_000_000_000)
        late = new_ulid(now_ms=2_000_000_000_000)
        assert len(early) == len(late) == 26
        assert early < late

    def test_roundtrips_its_timestamp(self):
        assert ulid_timestamp_ms(new_ulid(now_ms=1_700_000_000_123)) == 1_700_000_000_123

    def test_is_unique_across_many_draws(self):
        # Same millisecond, 80 bits of randomness: collisions must not happen.
        drawn = {new_ulid(now_ms=1_700_000_000_000) for _ in range(5_000)}
        assert len(drawn) == 5_000


class TestUid:
    def test_generates_and_parses_typed_uids(self):
        uid = Uid.generate("per")
        parsed = Uid.parse(str(uid))
        assert parsed == uid
        assert str(uid).startswith("per_")

    def test_rejects_unknown_prefix(self):
        with pytest.raises(IdentifierError):
            Uid.generate("xyz")
        with pytest.raises(IdentifierError):
            Uid.parse("zzz_01J8Z3K7QF9M2C4V6X8B0N5RTD")

    def test_typed_parse_prevents_cross_entity_confusion(self):
        """Type safety still applies across *entity kinds* — a dossier UID
        cannot stand in for a person. It deliberately no longer distinguishes
        patient from professional, because one person can be both."""
        dossier = str(Uid.generate("dos"))
        with pytest.raises(IdentifierError, match="person"):
            Uid.parse_typed(dossier, "per")

    @pytest.mark.parametrize(
        "malformed", ["", "per", "per_", "per_short", "PER_01J8Z3K7QF9M2C4V6X8B0N5RTD"]
    )
    def test_rejects_malformed(self, malformed):
        with pytest.raises(IdentifierError):
            Uid.parse(malformed)


class TestAhvn13:
    @pytest.mark.parametrize(
        "value",
        ["756.1234.5678.97", "7561234567897", "756.9217.0769.85"],
    )
    def test_accepts_valid_numbers_with_or_without_dots(self, value):
        assert Ahvn13.is_valid(value)

    @pytest.mark.parametrize(
        "value",
        [
            "756.1234.5678.98",  # wrong check digit
            "757.1234.5678.97",  # wrong country prefix
            "756.1234.5678",  # too short
            "756.1234.5678.9a",  # not numeric
            "",
            None,
        ],
    )
    def test_rejects_invalid_numbers(self, value):
        assert not Ahvn13.is_valid(value)

    def test_never_reveals_itself_in_string_form(self):
        """A logged AHV number is a reportable data breach, so the repr must
        not contain one."""
        ahvn = Ahvn13.parse("756.1234.5678.97")
        assert "1234" not in repr(ahvn)
        assert "1234" not in str(ahvn)
        assert "1234" not in f"{ahvn}"
        assert ahvn.masked() == "756.****.****.97"

    def test_reveal_is_the_only_way_to_the_digits(self):
        ahvn = Ahvn13.parse("756.1234.5678.97")
        assert ahvn.reveal() == "7561234567897"
        assert ahvn.formatted() == "756.1234.5678.97"

    def test_equality_is_by_value(self):
        assert Ahvn13.parse("756.1234.5678.97") == Ahvn13.parse("7561234567897")


class TestCheUid:
    @pytest.mark.parametrize("value", ["CHE-109.322.551", "CHE109322551", "che-105.805.649"])
    def test_accepts_valid(self, value):
        assert CheUid.is_valid(value)

    @pytest.mark.parametrize(
        "value", ["CHE-109.322.552", "CHE-109.322.55", "109.322.551", ""]
    )
    def test_rejects_invalid(self, value):
        assert not CheUid.is_valid(value)

    def test_formats_canonically(self):
        assert CheUid.parse("CHE109322551").formatted() == "CHE-109.322.551"


class TestGtin:
    @pytest.mark.parametrize("value", ["7601000000002", "4056186000002", "76123450"])
    def test_accepts_valid(self, value):
        assert is_valid_gtin(value)

    @pytest.mark.parametrize("value", ["7601000000003", "12345", "abcdefgh", ""])
    def test_rejects_invalid(self, value):
        assert not is_valid_gtin(value)


class TestSpid:
    """The EPR-SPID: 18 digits, prefix 761 — *not* the AHVN13's 13."""

    def test_is_eighteen_digits(self):
        spid = spid_from_entropy(bytes(range(16)))
        assert len(spid) == SPID_LENGTH == 18
        assert spid.startswith("761")
        assert is_valid_spid(spid)
        assert format_spid(spid) == spid

    def test_a_thirteen_digit_value_is_not_a_spid(self):
        """The classic Swiss integration bug: treating an AHVN13-shaped value
        as an EPR-SPID."""
        assert not is_valid_spid("7561234567897")
        with pytest.raises(IdentifierError, match="18 digits"):
            format_spid("7561234567897")

    def test_is_deterministic_in_its_entropy(self):
        entropy = b"\x11" * 16
        assert spid_from_entropy(entropy) == spid_from_entropy(entropy)

    def test_refuses_the_ahv_prefix_by_construction(self):
        """761, not 756: a derived identifier must never look like an AHV
        number, or downstream systems will treat it as one."""
        assert not spid_from_entropy(b"\x00" * 16).startswith("756")
        assert not is_valid_spid("756" + "0" * 15)

    def test_rejects_a_wrong_check_digit(self):
        spid = spid_from_entropy(bytes(range(16)))
        broken = spid[:-1] + str((int(spid[-1]) + 1) % 10)
        assert not is_valid_spid(broken)

    def test_rejects_insufficient_entropy(self):
        with pytest.raises(IdentifierError, match="128 bits"):
            spid_from_entropy(b"\x01\x02")


class TestSwissProfessionalIdentifiers:
    @pytest.mark.parametrize("gln", ["7601000000002", "7602000000009"])
    def test_accepts_a_valid_gln(self, gln):
        assert is_valid_gln(gln)

    @pytest.mark.parametrize("gln", ["7601000000003", "760100000000", "abcdefghijklm"])
    def test_rejects_an_invalid_gln(self, gln):
        assert not is_valid_gln(gln)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("A123456", "A123456"), ("a.123456", "A123456"), (" C654321 ", "C654321")],
    )
    def test_normalises_a_zsr_number(self, raw, expected):
        assert normalise_zsr(raw) == expected

    @pytest.mark.parametrize("raw", ["123456", "AA12345", "A12345", ""])
    def test_rejects_an_invalid_zsr_number(self, raw):
        assert not is_valid_zsr(raw)


class TestSwissProductIdentifiers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("62536", "62536"), ("62536 001", "62536-001"), ("62536-1", "62536-001")],
    )
    def test_normalises_a_swissmedic_authorisation(self, raw, expected):
        assert normalise_swissmedic_authorisation(raw) == expected

    @pytest.mark.parametrize("raw", ["625", "1234567890", "abcde", ""])
    def test_rejects_an_invalid_authorisation_number(self, raw):
        assert not is_valid_swissmedic_authorisation(raw)

    @pytest.mark.parametrize("raw", ["1234567", "0001234", "1"])
    def test_accepts_a_pharmacode(self, raw):
        assert is_valid_pharmacode(raw)

    @pytest.mark.parametrize("raw", ["12345678", "abc", ""])
    def test_rejects_an_invalid_pharmacode(self, raw):
        assert not is_valid_pharmacode(raw)

    @pytest.mark.parametrize("raw", ["C09AA03", "C09AA", "C09A", "C09", "C"])
    def test_accepts_atc_codes_at_every_depth(self, raw):
        assert is_valid_atc(raw)

    @pytest.mark.parametrize("raw", ["09AA03", "CC9AA03", "C0", ""])
    def test_rejects_an_invalid_atc_code(self, raw):
        assert not is_valid_atc(raw)


class TestVeka:
    def test_accepts_a_well_formed_card_number(self):
        assert is_valid_veka("80756" + "0" * 15)

    @pytest.mark.parametrize(
        "raw", ["80756", "8075600000000000000", "90756000000000000000", ""]
    )
    def test_rejects_a_malformed_card_number(self, raw):
        assert not is_valid_veka(raw)
