# Kanon — Website Spec

A self-contained brief for designer + frontend to build kanon.id (or chosen domain). Defines
information architecture, every page's content blocks, the visual + illustration system,
component library, copy hooks, asset inventory, accessibility/SEO floor, and the deliverable
checklist. Treat numbered IDs (`P-xx`, `I-xx`, `C-xx`) as the canonical references.

---

## 0. North star

**Product:** Kanon — a W3C-compliant Self-Sovereign Identity protocol on Hyperledger Besu.
Organizations register, get governance-approved, then issue verifiable credentials. Holders
present credentials either as cheap one-time-use bearer claims (Tier 1) or as zero-knowledge
proofs (Tier 2). Everything is governed via on-chain RBAC + timelocked multisig.

**Promise the site must convey, in this order:**
1. *Identity that organizations can actually govern* — not just self-sovereign keys.
2. *Two ways to prove*, picked by context: cheap-and-fast or private-and-unlinkable.
3. *Open and W3C-compatible*, interoperable with the wider DID/VC ecosystem.

**Audiences (in priority order):**
- **A1 — Engineering decision-makers** (CTOs, platform leads at orgs that issue credentials).
  Want: trust model, security posture, integration cost, compliance fit.
- **A2 — Developers** implementing issuance/verification. Want: docs, SDK, runnable examples.
- **A3 — Policy / compliance / digital-identity program owners.** Want: regulatory framing
  (eIDAS 2.0, EUDI Wallet, W3C standards), governance story, audits.
- **A4 — SSI community / open-source contributors.** Want: roadmap, spec, comparison with
  Indy / `did:ethr` / Aries.

Single brand voice: **technical, calm, plain-spoken.** No "revolutionary." No emoji in body
copy. Headlines can be punchy; subheads should be specific.

**Open brand decisions (designer should pin in v0 review):**
- Domain (`kanon.id` / `kanon.dev` / `usekanon.com` — TBD)
- Logotype style (wordmark vs symbol+wordmark)
- Mascot or no mascot (recommendation: no — institutional credibility matters more than
  charm for A1/A3)

---

## 1. Information architecture

```
/                                       Home (P-01)
/why-kanon                              Why Kanon (P-02)
/how-it-works                           How it works (P-03)
/use-cases                              Use cases index (P-04)
  /use-cases/regulated-issuance         (P-04a)
  /use-cases/employer-credentials       (P-04b)
  /use-cases/age-and-residency-gates    (P-04c)
  /use-cases/consortium-trust-lists     (P-04d)
/governance                             Governance model (P-05)
/security                               Security & audits (P-06)
/comparisons                            Comparisons index (P-07)
  /comparisons/vs-indy-on-besu          (P-07a)
  /comparisons/vs-did-ethr              (P-07b)
  /comparisons/vs-anoncreds             (P-07c)
/standards                              Standards & compliance (P-08)
/roadmap                                Roadmap (P-09)
/about                                  About / team (P-10)
/contact                                Contact / partner inquiry (P-11)
/legal/terms                            Terms (P-12)
/legal/privacy                          Privacy (P-13)
/legal/responsible-disclosure           Responsible disclosure (P-14)

/docs                                   Docs hub (P-20)
  /docs/quickstart                      Quickstart (P-21)
  /docs/concepts/...                    Concepts (P-22)
      did-kanon-method
      verifiable-credentials
      two-tier-presentations
      org-governance
      trust-model
      glossary
  /docs/architecture                    Architecture overview (P-23)
  /docs/contracts/...                   Contract reference (P-24)
      organization-registry
      did-registry
      schema-registry
      credential-definition-registry
      merkle-state-registry
      halo2-verifier-registry
      kanon-timelock
  /docs/sdk/...                         SDK reference (P-25)
      core
      issuer
      holder
      verifier
      orchestrator
  /docs/guides/...                      Guides / tutorials (P-26)
      issue-first-credential
      build-a-gated-dapp
      revoke-and-rotate
      run-an-issuer-service
      integrate-with-veramo
      ship-a-verifier
  /docs/operations/...                  Operations (P-27)
      deploy
      monitoring
      key-custody
      incident-response
      upgrade-procedure
  /docs/security                        Security posture & audit log (P-28)
  /docs/changelog                       Changelog (P-29)

/blog                                   Blog index (P-30)
  /blog/[slug]                          Blog post template (P-31)

/community                              Community (P-32) — Github, Discord, mailing list
/status                                 Service status (P-33) — testnet uptime, indexer lag

/explorer                               (optional) live explorer (P-40)
                                         — orgs, schemas, credDefs, root history
/playground                             (optional) interactive ZK proof demo (P-41)
```

**Persistent navigation:**

- **Top bar:** Logo, Product (Why / How / Use cases / Security / Comparisons), Docs, Blog,
  Roadmap, GitHub, "Get started" CTA.
- **Footer:** four columns — Product, Developers, Company, Legal — plus mailing-list signup,
  social, status badge, language switch (placeholder), copyright.

**Docs IA gets its own left rail** (sticky), top tabs for top-level docs sections, search
modal triggered by `⌘K`.

---

## 2. Visual system

### 2.1 Mood

- **Reference points:** Linear (precision + restraint), Stripe Docs (clarity + density),
  Spruce/Veramo (SSI seriousness), Aztec (cryptographic gravity). Avoid: web3-bro neon,
  generic gradient SaaS, kid-friendly mascots.
- **One-line direction:** *quietly futuristic, document-grade, with hand-drawn cryptographic
  glyphs.*

### 2.2 Color (designer to refine in token JSON)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#FBFAF7` (warm paper) | `#0C0E12` | page background |
| `--surface` | `#FFFFFF` | `#13161B` | cards, code blocks |
| `--ink` | `#0E1116` | `#F2F0EA` | body |
| `--ink-muted` | `#525866` | `#A4ABB6` | secondary text |
| `--rule` | `#E5E2D9` | `#22262E` | borders, dividers |
| `--accent` | `#3E5FD9` (kanon blue) | `#6F8BFF` | links, primary CTA |
| `--accent-soft` | `#E6ECFC` | `#1A2240` | tinted blocks |
| `--seal` | `#8B5CF6` (governance violet) | `#A78BFA` | org / governance signals |
| `--proof` | `#0F9F84` (verified teal) | `#3BC6A8` | ZK / verified signals |
| `--warn` | `#C76A2A` | `#E0884B` | suspended / stale-root |
| `--danger` | `#B0312B` | `#E25E58` | revocation, errors |
| `--code-bg` | `#F4F1EA` | `#0E1116` | inline code |

Three roles for the two accent hues are load-bearing: **blue = "Kanon brand / actions",
violet = "org & governance", teal = "ZK & verification".** They map to illustrated glyphs
(see §3) so the meaning stays consistent across hero art, docs diagrams, and UI.

### 2.3 Typography

- **Display / H1–H2:** a humanist serif with technical cuts. *Recommendation:* IBM Plex
  Serif or Söhne Breit (paid). Fallback: Newsreader (free).
- **Body / UI / H3+:** Inter (variable). Trustworthy, dense at 15px.
- **Mono:** JetBrains Mono. Used in docs + code-callouts in marketing.
- **Scale (rem, 1rem = 16px):** 0.75 / 0.875 / 1 / 1.125 / 1.25 / 1.5 / 1.875 / 2.5 / 3.25 / 4.5.
- **Headlines:** tight tracking (-0.02em), max-width ~24ch on hero, 32ch on section headers.
- **Body:** 1.6 line-height, max-width 68ch.

### 2.4 Layout, spacing, motion

- **12-column grid**, 1200 max content, 80px outer gutter desktop / 24px mobile.
- **Spacing tokens:** 4 / 8 / 12 / 16 / 24 / 32 / 48 / 64 / 96 / 128.
- **Radius:** 6 (controls), 12 (cards), 20 (hero panels).
- **Shadows:** one elevation only — `0 1px 2px rgba(0,0,0,.06), 0 8px 24px rgba(14,17,22,.06)`.
- **Motion:** 180–240ms, ease-out-cubic. Reserve longer (600ms) only for hero illustration
  reveal. Respect `prefers-reduced-motion`.

### 2.5 Components (library)

| ID | Component | Notes |
|---|---|---|
| C-01 | TopNav (sticky, blur on scroll) | Logo, primary nav, GitHub stars badge, "Get started" |
| C-02 | Footer | Four columns + mailing list |
| C-03 | Hero (centered, eyebrow + H1 + sub + two CTAs + hero illustration slot) | Used on P-01, P-02, P-04* |
| C-04 | FeatureTriad (3 cards w/ icon + heading + body + link) | P-01, P-02 |
| C-05 | SplitFeature (image-left / text-right, alternating) | P-02, P-03 |
| C-06 | DiagramFrame (numbered steps, illustration + caption) | P-03 |
| C-07 | TwoTierToggle (interactive switch comparing Tier 1 vs Tier 2 outcomes) | P-03 §2 |
| C-08 | CompareTable (sticky header, tooltip on terms) | P-07*, P-08 |
| C-09 | UseCaseCard (hero icon, title, "for X who Y", "concrete win", link) | P-04 |
| C-10 | CodeTabs (lang switcher, copy button, line highlight) | docs + landing |
| C-11 | CalloutBox (info / warn / danger / success) | docs |
| C-12 | StatusPill (Approved / Suspended / Live / Audited) | P-06, P-09 |
| C-13 | ContractCard (name, address-placeholder, role badges, "see ABI") | P-24 |
| C-14 | SDKCard (package name, install snippet, link) | P-25 |
| C-15 | TimelineBar (roadmap quarters horizontal, hover for detail) | P-09 |
| C-16 | TrustBar (logo strip) | P-01 (only when we have real logos) |
| C-17 | CTASection (full-bleed, big H2 + button) | every page bottom except docs |
| C-18 | DocsLeftRail (collapsible tree, current-section highlight) | docs |
| C-19 | DocsTOC (right rail, sticky, scroll-spy) | docs article |
| C-20 | SearchModal (⌘K, recent + suggested + results) | docs |
| C-21 | Tag (small monochrome) | blog, changelog |
| C-22 | DataBlock (label + monospace value + copy) | docs reference |
| C-23 | Stepper (numbered vertical) | guides, ops |
| C-24 | ProofBadge (animated SVG showing "proof verified") | hero + P-03 |
| C-25 | RegistryMap (interactive SVG of 6 registries + lines) | P-23 |

---

## 3. Illustration system

### 3.1 Style

- Hand-drawn line art over flat fills. **Two-tone per illustration** (accent + neutral),
  occasional third tone for emphasis. Pen weight 1.5px constant. No drop shadows.
- Subject matter draws on **seals, scrolls, keys, stamps, vaults, lattices, trees** —
  cryptographic primitives rendered as artisanal objects. Think *medieval scriptorium meets
  cryptographic protocol*.
- Type inside illustrations: handwritten lowercase, IBM Plex Mono italic.
- **No** human silhouettes in 3/4 view, no devices/laptops, no "data flowing through cloud."
- Light/dark variants delivered together.

### 3.2 Master asset inventory

Designer delivers SVG + dark variant + 2x PNG fallback for each. File naming `kanon-<id>-<short>.svg`.

| ID | Title | Where | Brief |
|---|---|---|---|
| I-01 | **The Seal** | hero, P-01, P-02 | A wax seal halfway pressed onto folded paper. Embossed sigil = stylized "K" intertwined with a Merkle tree fragment. Conveys "credential as artifact." Primary hero. |
| I-02 | **Two Paths** | P-03 §2 (Two-tier toggle) | A scroll splits into two ribbons mid-air: one short, marked with a tally count (Tier 1, single-use); one long, veiled by smoke at the bottom (Tier 2, unlinkable). |
| I-03 | **The Council** | P-05 (Governance) | A circular table with seven seal-rings interlocked, one marked "root", three marked "signers", three empty (representing the threshold). |
| I-04 | **The Tree** | P-03 §1, P-23 | A literal sparse Merkle tree drawn as branches; leaves are tiny envelopes; the root sits in a vault at the top. Internal nodes have hash marks. |
| I-05 | **The Vault** | P-06 (Security), P-27 ops | A safe with a thick door, a pairing-curve glyph etched into the metal, a HSM card inserted in the side. |
| I-06 | **The Lantern** | P-03 §3 (Privacy) | A hand holds a paper lantern; the silhouette inside is a credential (envelope) — outsiders see only the lantern's glow, not what's inside. Metaphor for ZK presentation. |
| I-07 | **The Quill** | P-03 §0 (Issuance) | An archivist's quill signing a small envelope; the wax seal next to it bears the org's sigil. |
| I-08 | **The Ledger** | P-23 (Architecture), comparisons | An open ledger book; rows are typed labels (Org, DID, Schema, CredDef, MerkleState, Verifier); spine is bound in violet. |
| I-09 | **The Key Ring** | P-22 (DID method), P-25 SDK | A ring of keys: Ed25519, secp256k1, BLS, JWK — each rendered with a slightly different bow style. |
| I-10 | **The Compass** | P-07 (Comparisons) | A brass compass; needle points to "Kanon" pole, with `did:ethr`, `did:indy:besu`, `did:web` engraved around the rim. |
| I-11 | **The Bridge** | P-08 (Standards) | A small footbridge between two cliffs labelled W3C and Kanon; planks are VC/DID standards. |
| I-12 | **The Hourglass** | P-05 §2 (Timelock) | An hourglass mid-fall; a tiny scroll labelled "proposal" sits at the neck. |
| I-13 | **The Beacon** | P-09 (Roadmap) | A coastal lighthouse with four windows lit, four dark — quarters of the year. |
| I-14 | **The Bench** | P-10 (About) | A stonemason's bench with chisels and a half-carved seal blank. Quietly humanist. |
| I-15 | **The Quarantine** | P-06 (Suspended org) | A folded scroll bound with a violet ribbon and a "do-not-read" wax cross. |
| I-16 | **The Burn Stamp** | P-03 §2 Tier-1 | A "spent" stamp pressed onto an envelope corner — the nullifier metaphor. |
| I-17 | **The Mirror** | P-22 (Verifier) | A hand mirror reflecting an envelope back — verifier checking, not collecting. |
| I-18 | **404 — The Misfiled Letter** | error page | A letter sliding between two filing cabinets; one is too small. |
| I-19 | **Empty state — The Empty Shelf** | docs empty search, etc. | A scriptorium shelf labelled "no entries yet" with a small inkwell. |
| I-20 | **Loading — The Pendulum** | spinners | A clock pendulum swinging; used only when load > 250ms. |

**Spot icons** (line-art, 24px, single accent stroke) — at least these:

`org`, `did`, `schema`, `credential-definition`, `merkle-root`, `verifier-registry`, `timelock`,
`pause`, `approve`, `suspend`, `member`, `holder`, `issuer`, `relying-party`, `tier-1`,
`tier-2`, `revoke`, `rotate`, `audit`, `precompile`, `besu`, `bls12-381`, `bn254`, `poseidon`,
`merkle-proof`, `nullifier`, `selective-disclosure`, `download-sdk`, `github`, `discord`,
`mail`, `external-link`, `copy`, `check`, `x-mark`, `info`, `warn`.

### 3.3 Diagrams (non-decorative, must be technically correct)

These are diagrams, not illustrations — designer should partner with engineering before
final art. Provide editable Figma source.

| ID | Diagram | Used on |
|---|---|---|
| D-01 | Org lifecycle (registered → approved → active → suspended → reactivated) | P-05 |
| D-02 | Issuance flow (issuer → keys/SMT → batchUpdate → CredentialAdded event) | P-03, P-22 |
| D-03 | Tier-1 presentation (holder presents secret credId + proof → consumeOneTime → event) | P-03 |
| D-04 | Tier-2 presentation (holder builds ZK proof → verifier.verify on-chain or off) | P-03 |
| D-05 | Six-registry map with role/trust arrows | P-23 |
| D-06 | Timelock proposal lifecycle (Safe propose → delay → execute / cancel) | P-05 |
| D-07 | Recent-roots sliding window (16-slot wheel + epoch ticks) | P-23, P-24 |
| D-08 | Two-tier comparison table morphing into the "Two Paths" illustration on hover | P-03 |

---

## 4. Page specs

For every page: **purpose**, **primary audience**, **content blocks** (top to bottom),
**illustrations**, **components**, **primary CTA**, **out-of-scope**.

> Copy hooks below are working drafts. Final copy should be edited by a writer, not adopted
> verbatim. Lengths are guides.

### P-01 — Home (`/`)

- **Purpose:** decision-makers grasp "what is Kanon" in ≤ 30s and self-route.
- **Audience:** A1 primary, A2 secondary.
- **Blocks:**
  1. **Hero (C-03).** Eyebrow: "SSI for organizations". H1 (≤ 9 words): *Identity infrastructure organizations can govern.*
     Sub (≤ 28 words): *Kanon is a W3C-compliant decentralized identity protocol on Hyperledger Besu. Approved organizations issue credentials. Holders prove things — cheaply, or in zero-knowledge.*
     Primary CTA: "Read the docs". Secondary CTA: "See the architecture".
     **Illustration:** I-01 The Seal (animated wax press on load).
  2. **Trust strip (C-16).** Placeholder slots for partner logos. Hidden until 3+ partners.
  3. **Three-pillar feature triad (C-04).**
     - *Organizations, not just keys.* Issuers go through a governance lifecycle on-chain.
     - *Two ways to prove.* Cheap one-time-use bearer credentials, or zero-knowledge presentations.
     - *Standards-aligned.* W3C DID Core 1.0, VC Data Model 2.0, designed to interoperate with `did:indy:besu`, `did:ethr`, and Aries.
  4. **How it works (split feature × 3, C-05).** Issuance → presentation → revocation.
     Each panel has one diagram (D-02, D-03/D-04, D-07) and ≤ 60 words.
  5. **For developers.** A short code block (`KanonClient.registerOrg(…)`) with copy button
     and link to quickstart. Illustration: I-09 Key Ring.
  6. **For decision-makers.** "Built for regulated issuance" — 3 bullets (governance lifecycle,
     timelocked upgrades, audit trail). Link to /governance and /security.
  7. **Comparisons teaser (C-08 mini).** Three tiny columns: Kanon vs `did:indy:besu` vs
     `did:ethr`. CTA: "Read the full comparison".
  8. **Closing CTA (C-17).** "Start with the quickstart" or "Talk to the team".
- **Components:** C-01..C-04, C-05, C-08-mini, C-10, C-16, C-17, C-24.
- **Illustrations:** I-01 (hero), I-02, I-04, I-06, I-09.
- **Out of scope:** detailed pricing, team bios.

### P-02 — Why Kanon (`/why-kanon`)

- **Purpose:** position vs the alternatives without trashing them. Earn A1 trust.
- **Blocks:**
  1. Hero. H1: *Identity, with a chain of custody.* Sub: framing about org-governance gap in
     existing SSI tooling. Illustration: I-03 The Council.
  2. **The gap.** Three-paragraph essay on why "decentralized identifier" alone isn't enough
     for regulated issuance — needs org governance, suspension, revocation, audit.
  3. **What Kanon adds.** SplitFeature × 4:
     a) On-chain organization lifecycle (D-01)
     b) Two-tier presentations (I-02)
     c) Timelocked governance (I-12, D-06)
     d) Standards-first interop (I-11)
  4. **What Kanon *doesn't* try to be.** Honest positioning — *not a wallet, not a
     blockchain, not a substitute for legal accreditation.*
  5. **When to choose something else.** A linked-out paragraph: if you need pure pseudonymous
     identity, `did:ethr`; if you need mature AnonCreds tooling today, `did:indy:besu`. Builds
     credibility.
  6. CTA: "See the architecture" → P-23.
- **Illustrations:** I-03, I-02, I-12, I-11, I-10.

### P-03 — How it works (`/how-it-works`)

- **Purpose:** explain mechanics to A1+A2 with diagrams.
- **Blocks:**
  1. Hero short. H1: *Five things happen on chain. The rest happens off.* Illustration I-04 The Tree.
  2. **Issuance.** D-02. Copy walks through: org approved → schema registered → credDef bound to issuer key → credentials minted off-chain → Merkle root committed.
  3. **Two ways to present (C-07 interactive toggle).** Tier 1 vs Tier 2 side by side. Diagrams D-03 and D-04 swap on toggle. Plain-English contrast: bearer claim-code vs unlinkable ZK proof.
  4. **Revocation.** Issuer updates root; presentations against old roots fall off the 16-epoch sliding window (D-07). Old credentials don't get "deleted" — they stop verifying.
  5. **Governance.** Suspension instantly stops issuance/revocation by the org; reactivation restores it. D-01 + I-15.
  6. **What you don't see.** Off-chain: holder wallets, verifier services, issuer signing services. Link out to SDK.
  7. CTA: "Run the quickstart".
- **Illustrations:** I-04, I-02, I-06, I-16, I-15.

### P-04 — Use cases (`/use-cases`)

- Index page with a 2×2 grid of UseCaseCards (C-09). Each card links to a sub-page.
- Hero H1: *Where on-chain governance changes the calculus.*
- **Sub-pages share a template:**
  1. "For X who Y" pitch (one sentence)
  2. Problem narrative (3 paragraphs, real-world flavor)
  3. How Kanon maps to it (3-4 bullets with spot icons)
  4. Architecture sketch (mini diagram, can reuse D-02/D-03)
  5. "What you'd need to build" (table: org setup, schema, credDef, issuer service, holder)
  6. Pull-quote from a hypothetical adopter (clearly marked as illustrative)
  7. CTA: read the relevant guide.

| Sub | Story |
|---|---|
| P-04a Regulated issuance | Banks / KYC providers issuing reusable credentials within a consortium. |
| P-04b Employer credentials | "Currently employed" / "role: nurse" — short-lived, revocable. |
| P-04c Age & residency gates | Holder proves attribute without revealing identifier. Tier 2 story. |
| P-04d Consortium trust lists | Cross-org schema sharing with org-gated cred-def issuance. |

### P-05 — Governance (`/governance`)

- **Purpose:** convince compliance leads we treat governance as first-class.
- **Blocks:**
  1. Hero. H1: *On-chain governance, off-chain consequences.* I-03 Council.
  2. **Role hierarchy table.** GOVERNANCE_ROLE / UPGRADER_ROLE / PAUSER_ROLE / CONFIG_ROLE / Org admin / Org member. Who holds each in dev vs prod.
  3. **Timelocked actions.** D-06. Diagram of propose → delay (configurable) → execute / cancel. Copy: "no admin action is instantaneous."
  4. **Org lifecycle (D-01).** Registered, approved, active, suspended, reactivated. Code-level enforcement: suspended orgs cannot issue or revoke.
  5. **Multisig posture.** Describe Safe-backed RootGovernance + recommended thresholds.
  6. **Auditability.** Every state-changing action emits an indexed event; list of events.
  7. CTA: "See the security page" → P-06.
- **Illustrations:** I-03, I-12, I-15, I-08.

### P-06 — Security & audits (`/security`)

- **Purpose:** honest disclosure of audit status, threat model, contact for responsible
  disclosure.
- **Blocks:**
  1. Hero. H1: *We document our security like we document our code.*
  2. **Threat model summary** (link to full doc): trust assumptions, RBAC, pause, upgrade.
  3. **Audit log.** Table: scope, auditor, date, report link, status pills (C-12). **Be
     truthful about what's still pending** — internal audits + V-* + P-* findings published.
  4. **Findings policy.** How findings are tracked publicly.
  5. **Responsible disclosure.** Email, PGP key, scope, safe-harbor language.
  6. **Phase-2 ZK security stance.** State plainly that Tier 2 is *not yet* on a live audited
     verifier; fail-closed until then. Don't bury this.
  7. **Operations posture.** HSM custody, monitoring, incident response → /docs/operations.
- **Illustrations:** I-05 Vault, I-12 Hourglass.

### P-07 — Comparisons (`/comparisons`)

- Index with three cards (vs Indy on Besu / vs did:ethr / vs AnonCreds). Hero I-10 Compass.
- **Each sub-page:**
  1. Side-by-side CompareTable (C-08) with rows: governance model, identifier shape, revocation, privacy, on-chain dependency, interop, audit/maturity, where each shines.
  2. Long-form essay: *when each is the right call*. Be generous to the other project — credibility outweighs marketing.
  3. Interop note: how Kanon interoperates with the alternative.
  4. CTA: read use cases.

### P-08 — Standards & compliance (`/standards`)

- **Blocks:**
  1. Hero I-11 Bridge.
  2. **Standards table.** W3C DID Core 1.0, VC Data Model 2.0, JSON-LD, Status List, BBS+,
     EIP-2537. Mark "supported" / "compatible" / "in progress".
  3. **Regulatory framing.** eIDAS 2.0 + EUDI Wallet brief, GDPR (off-chain credential
     content, on-chain commitments only), data-minimization.
  4. **Interoperability matrix.** Which other DID methods we resolve, and how.
  5. CTA: read about governance.

### P-09 — Roadmap (`/roadmap`)

- TimelineBar (C-15) horizontally; quarters of the year. Each milestone has a StatusPill
  (Planned / In progress / Shipped / Audited).
- Group by track: **Protocol**, **ZK / Tier 2**, **SDK / DX**, **Ecosystem / interop**,
  **Compliance / accreditation**.
- Be honest about what's done and what isn't. Mark *Halo2 verifier* / *Aztec Ignition SRS*
  / *Tier-2 GA* as Planned with truthful ETAs.
- Illustration: I-13 Beacon.

### P-10 — About (`/about`)

- **Blocks:** mission paragraph; team grid (optional — depends on whether team is public);
  values (engineering ethics, honesty about limitations); careers link.
- Illustration: I-14 The Bench.

### P-11 — Contact (`/contact`)

- Two intents: "Partner inquiry" form and "Talk to engineering" Calendly-style link.
- No public Slack/Discord embed (keep social to community page).

### P-12/13/14 — Legal

- Standard. Responsible-disclosure page is *not* generic — list the specific scope (contracts,
  circuit, SDK) and out-of-scope (third-party indexers, Besu itself).

### P-20 — Docs hub (`/docs`)

- Docs gets its own shell: top tabs (Quickstart / Concepts / Architecture / Contracts / SDK /
  Guides / Operations / Security / Changelog), left rail (C-18), main content, right TOC
  (C-19), ⌘K search (C-20).
- The hub page itself is a 3-column "what do you want to do?" router:
  - *Learn the model* → Concepts
  - *Build something* → Quickstart + Guides
  - *Operate it* → Operations
- Surfaces "popular pages" + "recently changed".

### P-21 — Quickstart (`/docs/quickstart`)

- One vertical stepper (C-23):
  1. Install SDK
  2. Connect to a Kanon deployment (testnet)
  3. Register an org (sample script)
  4. Get approval (testnet auto-approve flow described)
  5. Register a schema + credDef
  6. Issue a Tier-1 credential pool
  7. Build a gated dapp action
- Each step has CodeTabs (C-10), an expected output block, and "if you see X" troubleshooting.

### P-22 — Concepts

- Long-form, calm. Heavy on diagrams + spot icons. Glossary at the end.
- Recommended order: SSI primer → DIDs → VCs → Org governance → Two-tier proofs → Trust model → Glossary.
- Each page ends with "Next:" links.

### P-23 — Architecture (`/docs/architecture`)

- Hero D-05 Registry Map (interactive — hover a registry to show its responsibilities + role
  list + linked contract docs).
- Sections: Six registries; UUPS + ERC-7201 storage; AccessControl + Pausable + Timelock; Tier-1
  vs Tier-2 surfaces; off-chain components (SDK, issuer service, indexer); chain assumptions
  (Besu 26.5.0, EIP-2537, Cancun).
- Right rail TOC; long-form prose acceptable.

### P-24 — Contracts reference

- One page per registry + Timelock. Each page:
  - Purpose (one sentence)
  - Storage struct (DataBlock list, C-22)
  - Roles
  - Events
  - Functions table (signature + role gate + summary)
  - Errors table
  - Source link + audit status pill
- Use ContractCard (C-13) on the section index.

### P-25 — SDK reference

- One page per package (core, issuer, holder, verifier, orchestrator).
- Auto-generated TypeDoc embedded into the design (post-process to match site shell).
- Each page has SDKCard (C-14) at top with install snippet + version pill.

### P-26 — Guides

- Tutorial template: prerequisites → goal → steps (each is a stepper item with code, output,
  what just happened) → "where to go next".
- Listed: issue first credential / build a gated dapp / revoke + rotate / run an issuer
  service / integrate with Veramo / ship a verifier.

### P-27 — Operations

- Audience: A1 SRE / platform leads.
- Pages: Deploy, Monitoring, Key custody, Incident response, Upgrade procedure.
- Heavy use of Stepper (C-23) and CalloutBox (C-11).
- Illustration in section header: I-05 Vault.

### P-28 — Security posture

- Mirror P-06 but technical and timestamped. Describes the security posture, threat model,
  and links to `docs/SECURITY.md` in the repo.

### P-29 — Changelog

- Reverse-chronological. Each entry: date, version, tag (feature / fix / breaking / security),
  body. Filter by tag. Subscribe via RSS link in the corner.

### P-30 / P-31 — Blog

- Index: vertical list, each post = image (4:3, 16px radius) + title + 1-line excerpt + date
  + reading time + author.
- Post: Inter body, IBM Plex Mono code, max-width 68ch, sticky right TOC, "Subscribe" inline
  CTA after the second `<h2>`, hand-drawn illustration where helpful (designer pick from §3
  or commission new).

### P-32 — Community (`/community`)

- Github repo, Discord/Slack, mailing list, contribution guide, code of conduct, security
  contact, "this month in Kanon" summary.

### P-33 — Status (`/status`)

- Live status for testnet RPC, indexer freshness, audit log timestamp. Minimal — embed an
  off-the-shelf status page (StatusPage / Instatus) inside the site shell.

### P-40 — Explorer (*optional*, post-launch)

- Live read-only views: orgs (search, status filter), schemas, credential definitions, recent
  roots (sparkline), top issuers by volume, root history per credDef.
- Designed to look like the rest of the site — not a generic block-explorer skin.

### P-41 — Playground (*optional*, post-launch)

- Interactive ZK proof demo when Tier-2 ships. Browser-generated Halo2/Groth16 proof against
  a sample tree; on-chain verification on a testnet credDef; show timing + gas. Must explicitly
  mark "testnet only".

---

## 5. Cross-cutting requirements

### 5.1 SEO + metadata

- Per-page: `<title>` ≤ 60 chars, `<meta description>` 140–160 chars, OG image (1200×630),
  Twitter card large.
- Designer must produce **OG image templates** (one per top-level section: Home, Why, How,
  Docs, Comparisons, Blog) — title + subtitle slots + correct logo placement.
- Structured data (JSON-LD): `Organization` on `/`, `BreadcrumbList` on docs, `Article` on
  blog, `FAQPage` on the FAQ block in P-02.
- Canonical URLs, sitemap.xml, robots.txt.

### 5.2 Accessibility floor

- WCAG 2.2 AA. Color contrast ≥ 4.5:1 body, ≥ 3:1 large text and UI components.
- Every illustration has `alt`; *decorative* uses `aria-hidden="true"`.
- Diagrams have text-equivalent fallback (collapsed prose under the figure).
- Keyboard: tab order matches reading order, ⌘K opens search, `Esc` closes modals, `/` focuses
  search in docs.
- Focus ring is visible (2px accent outline, 2px offset). No focus-trap traps.
- `prefers-reduced-motion` removes hero illustration animation; static SVG remains.
- Captions for any video.

### 5.3 Performance budget

- LCP < 2.5s on a Moto G4 / Slow 4G.
- Hero image: SVG (≤ 30 KB) or AVIF ≤ 60 KB.
- No CLS from web fonts — use `font-display: swap` and reserve heights.
- Total JS < 150 KB compressed on home; docs can ramp to 250 KB for ⌘K + syntax highlighting.

### 5.4 Internationalization scaffolding

- Default English. Build with i18n routing from day 1 (Next.js `app/[locale]/…`) even if only
  one locale is enabled, so adding `de`, `es`, `pt`, `ja` later is structural, not surgical.

### 5.5 Analytics + consent

- Plausible (or PostHog self-hosted) for product analytics — privacy-first, no cookies needed.
- One single consent banner only if EU regs require it for chosen analytics.

### 5.6 Search

- Docs search via Algolia DocSearch (free for OSS) or Pagefind (static, no server). Pagefind
  is the cleaner first choice given the small surface.

---

## 6. Tech recommendation (frontend)

- **Framework:** Next.js 15 App Router on Vercel.
- **UI:** Tailwind v4 + shadcn/ui as the component primitive layer; add Radix primitives
  where shadcn falls short.
- **Docs:** MDX with rehype-pretty-code for syntax highlighting; Nextra alternative if the
  team prefers a docs-specific framework — but the rest of the site benefits from full
  App Router control, so MDX-in-Next is the default.
- **Content model:**
  - Marketing pages = MDX or TSX, hand-authored.
  - Docs = MDX in `content/docs`; metadata in frontmatter.
  - Blog = MDX in `content/blog`.
  - Generated reference (TypeDoc for SDK, solidity-docgen for contracts) ingested into MDX
    at build time, then themed.
- **State / interactivity:** keep client JS to interactive primitives only — `CodeTabs`,
  `TwoTierToggle`, `RegistryMap`, `SearchModal`. Everything else is RSC.
- **Animation:** Framer Motion only for hero reveal + page transitions.
- **Hosting:** Vercel. Edge runtime for `/api/search` (Pagefind static — no API needed),
  Node runtime if we add a contact form handler (Resend for email).

---

## 7. Deliverables — what the designer hands over

- [ ] **Brand kit:** logotype (SVG, lockups, monochrome variants), favicon set, OG templates
      (Figma + exported PNG/SVG).
- [ ] **Color tokens** in JSON (Tailwind-compatible) + a light/dark Figma styles file.
- [ ] **Typography styles** (Figma text styles) for the scale defined in §2.3.
- [ ] **Icon set** (every icon in §3.2 §spot icons), 24px, 1.5 stroke, SVG.
- [ ] **Illustration set** (I-01 through I-20), SVG + dark variants, each with a 2× PNG
      fallback for raster contexts.
- [ ] **Diagrams** (D-01 through D-08) as editable Figma frames + exported SVG.
- [ ] **Component library** in Figma (C-01 through C-25), with hover/focus/disabled states.
- [ ] **High-fidelity page mockups** at desktop (1440), tablet (768), mobile (375) for at
      least P-01, P-02, P-03, P-05, P-06, P-07, P-09, P-20, P-21, P-22 (concept article),
      P-23, P-24 (contract page), P-25 (SDK page), P-31 (blog post), P-18 (404).
- [ ] **Empty states + error states** (I-18, I-19, I-20, plus per-component).
- [ ] **Motion spec sheet** for hero reveal, CodeTabs switch, search modal open/close.
- [ ] **Handoff doc** mapping Figma components → C-IDs in §2.5, and illustrations → I-IDs in §3.2.

---

## 8. Open decisions (designer + product to close)

| # | Decision | Default if not chosen |
|---|---|---|
| O-1 | Brand mark: wordmark only vs symbol+wordmark | wordmark only |
| O-2 | Domain | `kanon.id` if available, else `usekanon.com` |
| O-3 | Show explorer (P-40) at launch | no — post-launch |
| O-4 | Show playground (P-41) at launch | no — when Tier-2 ships |
| O-5 | Public team page (P-10) | yes |
| O-6 | Dark mode at launch | yes, with light as default |
| O-7 | Languages at launch | English only, i18n scaffolded |
| O-8 | Analytics tool | Plausible |
| O-9 | Search tool | Pagefind |
| O-10 | Newsletter ESP | Buttondown |
| O-11 | Contact form backend | Resend + a single `/api/contact` route |
| O-12 | Logo strip on home (C-16) | hidden until 3+ real partners |

---

## 9. Launch checklist (one screen of items, in order)

1. Brand kit + Figma library accepted by product.
2. Page set P-01..P-09 final design.
3. Docs shell + P-20..P-23 final.
4. Component library implemented + Storybook (or equivalent).
5. MDX pipeline + first 5 docs pages migrated.
6. Auto-generated reference pages (P-24, P-25) ingested.
7. SEO/OG/structured data audited.
8. Accessibility audit (axe + manual keyboard pass).
9. Performance audit on mobile 4G.
10. Responsible-disclosure page live + security contact configured.
11. Analytics + status page live.
12. Pre-launch review with engineering on diagrams (D-01..D-08) for technical accuracy.
13. Soft launch (no homepage CTA blast) → 1-week monitoring → public launch.

---

## 10. Don'ts (kept short)

- No stock photography of "diverse business people."
- No marketing claims about audits we haven't had.
- No hiding the ZK Tier-2 status — it's a feature of our voice that we say what's working
  and what isn't.
- No autoplay video.
- No interstitial cookie banner unless legally required by analytics choice.
- No proprietary SSI jargon without a glossary entry.
- No "powered by web3" framing — talk about org-governed identity, not crypto.
