"""Identifier primitives: UIDs, AHVN13, CHE UID, GTIN, SPID."""

from __future__ import annotations

import pytest

from ehealth.domain.uid import (
    Ahvn13,
    CheUid,
    IdentifierError,
    Uid,
    format_spid,
    is_valid_gtin,
    is_valid_spid,
    new_ulid,
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
        uid = Uid.generate("pat")
        parsed = Uid.parse(str(uid))
        assert parsed == uid
        assert str(uid).startswith("pat_")

    def test_rejects_unknown_prefix(self):
        with pytest.raises(IdentifierError):
            Uid.generate("xyz")
        with pytest.raises(IdentifierError):
            Uid.parse("zzz_01J8Z3K7QF9M2C4V6X8B0N5RTD")

    def test_typed_parse_prevents_cross_entity_confusion(self):
        visitor = str(Uid.generate("vis"))
        with pytest.raises(IdentifierError, match="patient"):
            Uid.parse_typed(visitor, "pat")

    @pytest.mark.parametrize(
        "malformed", ["", "pat", "pat_", "pat_short", "PAT_01J8Z3K7QF9M2C4V6X8B0N5RTD"]
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
    def test_derives_a_checksum_valid_sector_id(self):
        spid = spid_from_entropy(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert len(spid) == 13
        assert spid.startswith("761")
        assert is_valid_spid(spid)
        assert is_valid_spid(format_spid(spid))

    def test_is_deterministic_in_its_entropy(self):
        entropy = b"\x11" * 16
        assert spid_from_entropy(entropy) == spid_from_entropy(entropy)

    def test_refuses_the_ahv_prefix_by_construction(self):
        """761, not 756: a derived identifier must never look like an AHV
        number, or downstream systems will treat it as one."""
        assert not spid_from_entropy(b"\x00" * 8).startswith("756")

    def test_rejects_insufficient_entropy(self):
        with pytest.raises(IdentifierError):
            spid_from_entropy(b"\x01\x02")
