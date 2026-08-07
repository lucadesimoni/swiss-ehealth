# Licence choice

**AGPL-3.0-or-later.** SPDX: `AGPL-3.0-or-later`. Full text in
[`LICENSE`](../LICENSE), identifier on every source file.

The brief was: the best open source licence for Switzerland, independent of the
USA and the EU. This is the reasoning, including where the brief cannot be
satisfied literally.

## What "independent" can actually mean

A licence cannot be made to belong to a country. Three things are worth
separating, because only two of them matter legally:

1. **Choice of law and venue clauses.** These genuinely bind you to a foreign
   legal system. This is the decisive criterion.
2. **Enforceability under Swiss law.** Some clauses are void here regardless of
   what the licence says.
3. **The postal address of the organisation that drafted the text.** This has
   no legal effect at all.

The AGPL, like the GPL and Apache-2.0, contains **no choice-of-law clause and no
venue clause**. Between Swiss parties, a dispute is therefore governed by Swiss
law and heard by Swiss courts under the ordinary rules (CPC / IPRG). That is the
strongest form of independence a widely-used licence offers.

The FSF is a US non-profit, and no serious open source licence is drafted in
Switzerland. If the requirement were read literally — nothing authored outside
CH — the answer would be "no usable licence exists", which serves nobody. The
criterion that carries legal weight is jurisdiction, and on that the AGPL is
neutral.

## Why not the EUPL

The EUPL is the obvious candidate for a European public-sector project, and it
is the one the brief rules out — correctly, and for a concrete reason rather
than a political one:

> **EUPL-1.2, Article 15:** governed by the law of the EU Member State where the
> Licensor resides; for disputes involving EU institutions, **Belgian law** and
> the **Court of Justice of the European Union**.

A Swiss licensor is not resident in a Member State, so the clause does not even
map cleanly onto them, and where it does bite it imports EU law and CJEU
jurisdiction. For a health record built on Swiss data sovereignty that is the
opposite of what is wanted. CeCILL (French law) fails for the same reason.

## Why AGPL rather than GPL, MPL or Apache

The system is a **network service**. Someone will want to run it as hosted
infrastructure. That single fact decides the licence:

| Licence | Choice-of-law | Network use | Consequence here |
|---|---|---|---|
| **AGPL-3.0** | none | **covered (§13)** | a hosted fork must publish its source |
| GPL-3.0 | none | not covered | a cloud provider can run a closed modified fork |
| MPL-2.0 | none (removed in 2.0) | not covered | same, plus only file-level copyleft |
| Apache-2.0 | none | not covered | permissive; proprietary forks are fine |
| EUPL-1.2 | **EU / Belgian** | covered | copyleft is right, jurisdiction is wrong |

AGPL §13 is the whole point. Without it, a foreign hyperscaler can take this
code, adapt it into a closed hosted EPD platform, and the Swiss community that
paid for it gets nothing back — the exact dependency the sovereignty
requirement exists to prevent. With it, anyone who *operates* a modified version
for others must offer those users its source.

Note what AGPL does **not** do: it does not stop anyone from running this,
including commercially, including abroad. It requires that modifications made
available as a service come back. That is the trade, and it is the right one for
public health infrastructure.

MPL-2.0 deserves a mention as runner-up: it deliberately dropped the California
choice-of-law and venue clauses that MPL 1.1 carried, making it genuinely
neutral. It loses only on the network question.

## Compatibility

- The repository previously carried **GPL-3.0**. GPLv3 → AGPLv3 is a permitted
  direction: GPLv3 §13 explicitly allows combining with AGPLv3 code, and the
  relicensing is possible here only because the sole copyright holder is the
  repository owner and there were no third-party contributions at the time of
  the change. **This is not repeatable once outside contributions exist**
  without their agreement.
- AGPL-3.0 code may be combined with GPL-3.0 code; the combined network-facing
  work is then subject to §13.
- All runtime dependencies (FastAPI, SQLAlchemy, Pydantic, cryptography,
  httpx, argon2-cffi) are MIT / BSD / Apache-2.0 / PSF, all AGPL-compatible.
  Apache-2.0 is one-way compatible with GPLv3 and AGPLv3, which is the direction
  used here.

## Under Swiss law, specifically

- **Liability.** AGPL §§15–16 disclaim all liability. Under **OR Art. 100(1)**
  an agreement excluding liability for *unlawful intent or gross negligence* is
  void, and Art. 100(2) lets a court set aside exclusions for slight negligence
  in some cases. The disclaimers therefore hold for ordinary negligence and no
  further. §17 anticipates this ("If the disclaimer … cannot be given local
  legal effect … reviewing courts shall apply local law that most closely
  approximates an absolute waiver").
- **Copyright.** URG Art. 16 governs transfer; a licence is a grant of use, not
  an assignment, and moral rights (URG Art. 9) stay with the author regardless.
- **Warranty.** Free-of-charge software is closest to a *Schenkung* (OR
  Art. 239 ff.), where the donor's warranty obligations are already minimal
  (Art. 248) — which aligns with the licence's own position.
- **Consumer protection** rules that constrain such disclaimers in a B2C setting
  are largely irrelevant here: the licensees are institutions and developers,
  not consumers.

None of this is legal advice. Before a public-sector deployment, have counsel
confirm the interaction with EMBAG (the federal open-source obligation, in force
since 2024) and with the procurement rules that apply to the operator.

## Contributions

Contributions are accepted under AGPL-3.0-or-later, inbound = outbound. There is
no CLA and no copyright assignment: contributors keep their copyright, which
means no single party — including any future foreign acquirer — can unilaterally
relicense the project away from copyleft. That is a sovereignty property in
itself, and it is the reason not to adopt a CLA later.

## Machine-readable compliance

Every source file carries an SPDX identifier:

```python
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
```

`tests/test_versioning.py` fails if any file under `src/` or `tests/` is
missing it, so licence metadata cannot silently rot. This follows the
[REUSE](https://reuse.software/) convention, which makes automated licence
audits of the whole tree possible without a human reading headers.
