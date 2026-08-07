"""Key hierarchy, AEAD binding, signatures, and AHVN13 pseudonymisation."""

from __future__ import annotations

import pytest

from ehealth.domain.identity import IdentityService
from ehealth.domain.uid import Ahvn13, is_valid_spid
from ehealth.security.crypto import (
    GENESIS_HASH,
    CryptoError,
    KeyPurpose,
    KeyRing,
    canonical_json,
    constant_time_equals,
    hash_chain_link,
)

ANNA = "756.1234.5678.97"
BEAT = "756.9217.0769.85"


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(b"\x2a" * 32)


class TestKeyRing:
    def test_rejects_a_short_root_key(self):
        with pytest.raises(CryptoError, match="entropy"):
            KeyRing(b"too short")

    def test_derives_stable_keys_from_the_root(self):
        first = KeyRing(b"\x01" * 32).key(KeyPurpose.FIELD_ENCRYPTION).material
        second = KeyRing(b"\x01" * 32).key(KeyPurpose.FIELD_ENCRYPTION).material
        assert first == second

    def test_separates_purposes(self, keyring):
        """Key separation must be structural: two purposes must never share
        material even though they come from one root."""
        a = keyring.key(KeyPurpose.FIELD_ENCRYPTION).material
        b = keyring.key(KeyPurpose.AUDIT_LEDGER).material
        assert a != b

    def test_separates_versions(self, keyring):
        assert (
            keyring.key(KeyPurpose.FIELD_ENCRYPTION, 1).material
            != keyring.key(KeyPurpose.FIELD_ENCRYPTION, 2).material
        )

    def test_key_ids_carry_the_version(self, keyring):
        assert keyring.key(KeyPurpose.FIELD_ENCRYPTION, 3).kid == "field-encryption.v3"


class TestEnvelopeEncryption:
    def test_roundtrips(self, keyring):
        envelope = keyring.encrypt(
            KeyPurpose.FIELD_ENCRYPTION, b"Muster", aad=b"field|pat_1|family_name"
        )
        assert keyring.decrypt(envelope, aad=b"field|pat_1|family_name") == b"Muster"

    def test_ciphertext_does_not_contain_the_plaintext(self, keyring):
        envelope = keyring.encrypt(
            KeyPurpose.FIELD_ENCRYPTION, b"Muster", aad=b"x"
        )
        assert "Muster" not in envelope

    def test_rejects_a_transplanted_ciphertext(self, keyring):
        """The AAD binds a ciphertext to one row and column, so moving it onto
        another patient's record fails loudly instead of decrypting."""
        envelope = keyring.encrypt(
            KeyPurpose.FIELD_ENCRYPTION, b"Muster", aad=b"field|pat_1|family_name"
        )
        with pytest.raises(CryptoError, match="authentication"):
            keyring.decrypt(envelope, aad=b"field|pat_2|family_name")

    def test_rejects_a_tampered_ciphertext(self, keyring):
        envelope = keyring.encrypt(KeyPurpose.FIELD_ENCRYPTION, b"Muster", aad=b"x")
        scheme, kid, nonce, ciphertext = envelope.split(".", 3)
        flipped = ciphertext[:-2] + ("AA" if ciphertext[-2:] != "AA" else "BB")
        with pytest.raises(CryptoError):
            keyring.decrypt(f"{scheme}.{kid}.{nonce}.{flipped}", aad=b"x")

    def test_decrypts_older_key_versions_after_rotation(self):
        """Rotation must not orphan existing data: v1 ciphertext stays
        readable while v2 is used for new writes."""
        old = KeyRing(b"\x07" * 32, {KeyPurpose.FIELD_ENCRYPTION: 1})
        envelope = old.encrypt(KeyPurpose.FIELD_ENCRYPTION, b"secret", aad=b"a")
        rotated = KeyRing(b"\x07" * 32, {KeyPurpose.FIELD_ENCRYPTION: 2})
        assert rotated.decrypt(envelope, aad=b"a") == b"secret"
        assert "v2" in rotated.encrypt(KeyPurpose.FIELD_ENCRYPTION, b"new", aad=b"a")

    @pytest.mark.parametrize(
        "envelope", ["", "garbage", "v1.bad", "v2.field-encryption.v1.aa.bb"]
    )
    def test_rejects_malformed_envelopes(self, keyring, envelope):
        with pytest.raises(CryptoError):
            keyring.decrypt(envelope, aad=b"a")


class TestSignatures:
    def test_signs_and_verifies(self, keyring):
        signer = keyring.signer(KeyPurpose.AUDIT_LEDGER)
        signature = signer.sign(b"payload")
        assert signer.verify(b"payload", signature)
        assert not signer.verify(b"payload!", signature)

    def test_a_different_key_version_does_not_verify(self, keyring):
        signature = keyring.signer(KeyPurpose.AUDIT_LEDGER, 1).sign(b"payload")
        assert not keyring.signer(KeyPurpose.AUDIT_LEDGER, 2).verify(b"payload", signature)


class TestCanonicalJson:
    def test_is_key_order_independent(self):
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_has_no_insignificant_whitespace(self):
        assert canonical_json({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


class TestHashChain:
    def test_is_order_sensitive(self):
        first = hash_chain_link(GENESIS_HASH, b"a")
        assert hash_chain_link(first, b"b") != hash_chain_link(GENESIS_HASH, b"b")

    def test_is_domain_separated(self):
        import hashlib

        assert hash_chain_link(GENESIS_HASH, b"a") != hashlib.sha256(
            GENESIS_HASH + b"a"
        ).digest()


def test_constant_time_equals_handles_both_types():
    assert constant_time_equals("abc", b"abc")
    assert not constant_time_equals("abc", "abd")


# --------------------------------------------------------------------------
# Pseudonymisation
# --------------------------------------------------------------------------


class TestIdentityService:
    @pytest.fixture
    def identity(self, keyring) -> IdentityService:
        return IdentityService(keyring)

    def test_pseudonym_is_deterministic(self, identity):
        """Determinism is what makes cross-institution patient matching work
        without anyone holding a plaintext register."""
        assert identity.ppid(Ahvn13.parse(ANNA)) == identity.ppid(Ahvn13.parse(ANNA))

    def test_different_people_get_different_pseudonyms(self, identity):
        assert identity.ppid(Ahvn13.parse(ANNA)) != identity.ppid(Ahvn13.parse(BEAT))

    def test_pseudonym_does_not_contain_the_ahv_number(self, identity):
        ppid = identity.ppid(Ahvn13.parse(ANNA))
        assert "7561234567897" not in ppid
        assert "1234" not in ppid

    def test_a_different_root_key_yields_a_different_pseudonym(self):
        """Without the sector key, a stolen database of pseudonyms cannot be
        joined against any other AHVN13-keyed system."""
        one = IdentityService(KeyRing(b"\x01" * 32)).ppid(Ahvn13.parse(ANNA))
        two = IdentityService(KeyRing(b"\x02" * 32)).ppid(Ahvn13.parse(ANNA))
        assert one != two

    def test_lookup_index_is_versioned_and_distinct_from_the_pseudonym(self, identity):
        ahvn = Ahvn13.parse(ANNA)
        index = identity.lookup_index(ahvn)
        assert index.startswith("v1:")
        assert index.split(":", 1)[1] != identity.ppid(ahvn)

    def test_spid_candidates_are_valid_deterministic_and_distinct(self, identity):
        candidates = []
        for candidate in identity.spid_candidates(Ahvn13.parse(ANNA)):
            candidates.append(candidate)
            if len(candidates) == 5:
                break
        assert all(is_valid_spid(c) for c in candidates)
        assert all(c.startswith("761") for c in candidates)
        assert len(set(candidates)) == 5
        # Re-deriving gives the same first candidate.
        assert next(iter(identity.spid_candidates(Ahvn13.parse(ANNA)))) == candidates[0]

    def test_derive_seals_the_ahv_number_bound_to_the_pseudonym(self, identity):
        derived = identity.derive(Ahvn13.parse(ANNA))
        assert derived.sealed_ahvn is not None
        assert "7561234567897" not in derived.sealed_ahvn
        recovered = identity.unseal(derived.sealed_ahvn, derived.ppid)
        assert recovered.reveal() == "7561234567897"

    def test_sealed_ahvn_cannot_be_moved_to_another_person(self, identity):
        derived = identity.derive(Ahvn13.parse(ANNA))
        other_ppid = identity.ppid(Ahvn13.parse(BEAT))
        with pytest.raises(CryptoError):
            identity.unseal(derived.sealed_ahvn, other_ppid)

    def test_zero_retention_mode_keeps_nothing(self, keyring):
        """A deployment can choose to be unable to re-identify at all."""
        identity = IdentityService(keyring, store_sealed_ahvn=False)
        derived = identity.derive(Ahvn13.parse(ANNA))
        assert derived.sealed_ahvn is None
        assert derived.ppid  # linkage still works

    def test_field_sealing_is_bound_to_entity_and_column(self, identity):
        envelope = identity.seal_field("pat_1", "family_name", "Muster")
        assert identity.open_field("pat_1", "family_name", envelope) == "Muster"
        with pytest.raises(CryptoError):
            identity.open_field("pat_2", "family_name", envelope)
        with pytest.raises(CryptoError):
            identity.open_field("pat_1", "given_name", envelope)
