# Delegation Circuit (ZKP 1)

## Inputs

- Public
   * **nf_signed**: a unique, deterministic identifier derived from a note's secret components that publicly marks the note as spent.
   * **rk**: the randomized public key for spend authorization. Derived per-transaction, publicly exposed, unlinkable, paired with `rsk` - the private key
   * **cmx_new**: the extracted note commitment (`ExtractP(cm_new)`) of the output note. A Pallas base field element (x-coordinate of the output note's commitment point). Published so the verifier knows which output note was created and can include it in the vote chain's commitment tree.
   * **gov_comm**: the governance commitment — a Pallas base field element identifying the governance context (e.g., a particular DAO or proposal framework). Scopes the delegation proof to a specific governance domain, preventing cross-governance replay.
   * **vote_round_id**: the vote round identifier — a Pallas base field element identifying the specific voting round or epoch. Prevents cross-round replay: a keystone signature for round N cannot be reused in round N+1.

- Private
   * **ρ** "rho": The nullifier of the note that was spent to create the signed note
   * **ψ** ("psi"): A pseudorandom field element derived from the note's random seed `rseed` and its nullifier domain separator rho
   * **cm**: The note commitment, witnessed as an ECC point
   * **nk**: nullifier key
   * **ak**: spend authorization validating key (the long-lived public key for spend authorization)
   * **alpha**: a fresh random scalar used to rerandomize the spend authorization key for each transaction.
   * **rivk**: is the randomness (blinding factor) for the CommitIvk Sinsemilla commitment. The name stands for randomness for incoming viewing key.
   * **rcm_signed**: the note commitment trapdoor (randomness). A scalar derived from `rseed` and `rho` that blinds the commitment.
   * **g_d_signed**: the diversified generator from the note recipient's address
   * **pk_d_signed**: the diversified transmission key from the note recipient's address
   * **g_d_new**: the diversified generator from the output note recipient's address. Free witness — not checked against `ivk` (see condition 7).
   * **pk_d_new**: the diversified transmission key from the output note recipient's address. Free witness — not checked against `ivk` (see condition 7).
   * **psi_new**: pseudorandom field element for the output note, derived from `rseed_new` and `rho_new`.
   * **rcm_new**: the output note commitment trapdoor (randomness), derived from `rseed_new` and `rho_new`.
   * **cmx_1, cmx_2, cmx_3, cmx_4**: the extracted note commitments (`ExtractP(cm_i)`) of the four notes being delegated. Each is a Pallas base field element (x-coordinate of the commitment point). Hashed together with `gov_comm` and `vote_round_id` to produce `rho_signed` in condition 3. Currently free witnesses; a future condition (condition 10) will derive them in-circuit.
   * **v_1, v_2, v_3, v_4**: the note values (in zatoshi) of the four delegated notes. Free witnesses summed in-circuit to produce `v_total`. Bound into `gov_comm` via condition 7; condition 9 will bind them to actual note commitments.
   * **gov_comm_rand**: a random blinding factor for the governance commitment. Prevents observers from brute-forcing the address or weight from the public `gov_comm`.

## 1. Signed Note Commitment Integrity

Purpose: ensure that the signed note commitment is correctly constructed. This establishes the link between spending authority, nullifier key and the note itself

What it proves:

The circuit recomputes the note commitment in-circuit from the note's witness data and constrains the result equal to the witnessed commitment `cm_signed`.

Establishes the binding link between `ak`, `nk` and the note itself `cm`

```
NoteCommit_rcm_signed(repr(g_d_signed), repr(pk_d_signed), 0, rho_signed, psi_signed) = cm_signed
```

Where
- **rcm_signed**: this is the note commitment randomness (also called the trapdoor). It is a scalar derived from the note's `rseed` and `rho`. It blinds the commitment so that two notes with identical contents produce different commitments. It appears as a subscript because of how Pedersen/Sinsemilla commitments work structurally:
`Commit_r(m) = Hash(m) + [r] * R`. So, expanded, the formula is really:
`cm_signed = SinsemillaHash(repr(g_d_signed) || repr(pk_d_signed) || 0 || rho_signed || psi_signed) + [rcm_signed] * R`
- **repr(g_d_signed)** - The diversified base point from the recipient's payment address. `g_d` is a point on the Pallas curve derived deterministically from the address's diversifier d. `repr()` extracts its canonical byte representation (the x and y coordinates). It ensures the commitment is bound to a specific diversified address. This value is witnessed privately and also used in the address integrity check (`pk_d = [ivk] * g_d`).
- **0**: The note value is hardcoded to zero since the "signed note" in this delegation context is always a dummy/zero-value note.
- **ρ** ("rho"): The nullifier of the note that was spent to create this note. It is a Pallas base field element that serves as a unique, per-note domain separator. rho ensures that even if two notes have identical contents, they will produce different nullifiers because they were created by spending different input notes. rho provides deterministic, structural uniqueness — it chains each note to its creation context. A single tx can create multiple output notes from the same input; all those outputs share the same rho. If nullifier derivation only used rho (no psi), outputs from the same input could collide.
- **ψ** ("psi"): A pseudorandom field element derived from the note's random seed `rseed` and its nullifier domain separator rho. It adds randomness to the nullifier so that even if two notes share the same rho and nk, they produce different nullifiers. We provide it as a witness instead of deriving in-circuit since derivation would require an expensive Blake2b. psi provides randomized uniqueness — it is derived from `rseed` which is freshly random per note. Even if multiple outputs are derived from the same note, different `rseed` values produce different psi values. But if uniqueness relied only on psi (i.e. only randomness), a faulty RNG would cause nullifier collisions. Together with rho, they cover each other's weaknesses. Additionally, there is a structural reason: if we only used psi, there would be an implicit chain where each note's identity is linked to the note that was spent to create it. The randomized psi breaks the chain, unblocking a requirement used in Orchard's security proof.
- **cm_signed** The witnessed note commitment, the value the prover claims is the commitment for this note. The circuit recomputes `NoteCommit` from all the above inputs and then enforces strict equality against this witnessed `cm_signed`. If any single parameter is wrong (wrong address, wrong randomness, wrong rho/psi), the derived commitment won't match and proof creation fails.

In essence, the commitment binds together: **who the note belongs to** (g_d, pk_d), **how much it's worth** (0), **where it came from** (rho), **random uniqueness** (psi), **all blinded by randomness** (rcm).

Note:
- The constraint is strict equality. No null option. If the commitment does not match, proof creation fails.

## 2. Signed Nullifier Integrity

Purpose: Derive the standard Orchard nullifier deterministically from the note's secret components. Validate it against the one we created exclusion proof from.

```
derive nf_signed = DeriveNullifier(nk, rho_signed, psi_signed, cm_signed)
```

Where:  
- **nk**: The nullifier deriving key associated with the note.

- **ρ** ("rho"): The nullifier of the note that was spent to create the signed note. It is a Pallas base field element that serves as a unique, per-note domain separator. rho ensures that even if two notes have identical contents, they will produce different nullifiers because they were created by spending different input notes. rho provides deterministic, structural uniqueness — it chains each note to its creation context. A single tx can create multiple output notes from the same input; all those outputs share the same rho. If nullifier derivation only used rho (no psi), outputs from the same input could collide.

- **ψ** ("psi"): A pseudorandom field element derived from the note's random seed `rseed` and its nullifier domain separator rho. It adds randomness to the nullifier so that even if two notes share the same rho and nk, they produce different nullifiers. We provide it as a witness instead of deriving in-circuit since derivation would require an expensive Blake2b. psi provides randomized uniqueness — it is derived from `rseed` which is freshly random per note. Even if multiple outputs are derived from the same note, different `rseed` values produce different psi values. But if uniqueness relied only on psi (i.e. only randomness), a faulty RNG would cause nullifier collisions. Together with rho, they cover each other's weaknesses. Additionally, there is a structural reason: if we only used psi, there would be an implicit chain where each note's identity is linked to the note that was spent to create it. The randomized psi breaks the chain, unblocking a requirement used in Orchard's security proof.

- **cm**: The note commitment, witnessed as an ECC point (the form `DeriveNullifier` expects). Converted from `NoteCommitment` to a Pallas affine point in-circuit.

**Function:** `DeriveNullifier`

**Type:**  
```
DeriveNullifier: 𝔽_qP × 𝔽_qP × 𝔽_qP × ℙ → 𝔽_qP
```

**Defined as:**  
```
DeriveNullifier_nk(ρ, ψ, cm) = ExtractP(
    [ (PRF_nf_Orchard_nk(ρ) + ψ) mod q_P ] * 𝒦_Orchard + cm
)
```

- `ExtractP` denotes extracting the base field element from the resulting group element.  
- `𝒦_Orchard` is a fixed generator. Input to the `EccChip`.
- `PRF_nf_Orchard_nk(ρ)` is the nullifier pseudorandom function as defined in the Orchard protocol. Uses Poseidon hash for PRF.

**Constructions**:
- `Poseidon`: used as a PRF function.
- `Sinsemilla`: provides infrastructure for the lookup tables of the ECC chip.


- **Why do we take PRF of rho?**
   * The primary reason is unlinkability. Rho is the nullifier of the note that was spend to create this note. In standard Orchard, nullifiers are published onchain. The PRF destroys the link.
- **Why not expose nf_old publicly?**
   * In standard Orchard, the nullifier is published to prevent double-spending. In this delegation circuit, nf_old is not directly exposed as a public input. Instead, it is checked against the exclusion interval and a domain nullifier is published instead. The standard nullifier stays hidden.

## 3. Rho Binding

Purpose: the signed note's rho is bound to the exact notes being delegated, the governance commitment, and the round. This is what makes the keystone signature non-replayable and scoped.

```
rho_signed = Poseidon(cmx_1, cmx_2, cmx_3, cmx_4, gov_comm, vote_round_id)
```

Where
- **cmx_1, cmx_2, cmx_3, cmx_4**: The extracted note commitments (`ExtractP(cm_i)`) of the four notes being delegated. Each `cmx_i` is a Pallas base field element — the x-coordinate of the corresponding note's commitment point. By hashing all four commitments into rho, the keystone signature is bound to the exact set of notes the delegator chose. Tampering with any single commitment changes the hash and invalidates the proof. Currently witnessed as free private inputs; a future condition (condition 10) will derive them in-circuit from the actual note data.
- **gov_comm**: The governance commitment — a Pallas base field element identifying the governance context.
- **vote_round_id**: The vote round identifier — a Pallas base field element identifying the specific voting round or epoch.

**Function:** `Poseidon` with `ConstantLength<6>`

Uses the same `Pow5Chip` / `P128Pow5T3` construction as the nullifier derivation, but with 6 inputs instead of 2. With rate 2, the sponge absorbs 2 elements per permutation round (3 absorption rounds for 6 inputs). The domain separator includes the input length, providing proper cryptographic separation from other Poseidon uses in the circuit.

**Constraint:** The circuit computes `derived_rho = Poseidon(cmx_1, cmx_2, cmx_3, cmx_4, gov_comm, vote_round_id)` and enforces strict equality `derived_rho == rho_signed`. Since `rho_signed` is the same value used in both note commitment integrity (condition 1) and nullifier integrity (condition 2), this creates a three-way binding: the nullifier, the note commitment, and the delegation scope are all tied to the same rho.

## 4. Spend Authority

Purpose: proves spending authority while preserving unlinkability. Links to the Keystone spend-auth signature out-of-circuit.
- Only the holder of `ask` can produce `rsk = ask + alpha` and sign under `rk`, proving they are authorized to spend the note.
- `alpha` is fresh randomness each time, the published `rk` reveals nothing about `ak` - different spends from the same wallet cannot be correlated by observers.

```
rk = SpendAuthSig.RandomizePublic(alpha, ak) 
```
i.e. rk = ak + [alpha] * G

Where:
- `ak` - the authorizing key, the long-lived public key for spend authorization.
- `alpha` - the fresh randomness published each time. If rk were the same across transactions, an observer could link them to the same spender.
- `G` - the fixed base generator point on the Pallas curve dedicated to the spend authorization.

Spend Authority: i.e. `rk = ak + [alpha] * G` — the public `rk` is a valid rerandomization of `ak`. Links to the Keystone signature verified out-of-circuit.

## 5. Diversified Address Integrity

Purpose: proves the signed note's address belongs to the same key material `(ak, nk)`. This is where `ivk` is established — it will be reused for every real note ownership check.

Without address integrity, the nullifier integrity proves:
- "I know (nk, rho, psi, cm) that produce this nullifier"
- "I know ak such that rk = ak + [alpha] * G".

But there is nothing that ties ak to nk. They are witnessed independently. A malicious prover could:
- Supply their own `ak` (i.e passes spend authority, can sign under `rk`)
- Supply someone else's `nk` (i.e. valid nullifier for someone else's note)

```
ivk = ⊥  or  pk_d_signed = [ivk] * g_d_signed
where ivk = CommitIvk_rivk(ExtractP(ak_P), nk)
```

What address integrity fixes:
- `CommitIvk(ExtractP(ak), nk)` forces `ak` and `nk` to come from the same key tree
- `pk_d_signed = [ivk] * g_d_signed` proves the note's destination address was derived from this specific ivk. This will be asserted on as part of validating note commitment integrity.

The `ivk = ⊥` case is handled internally by `CommitDomain::short_commit`: incomplete addition allows the identity to occur, and synthesis detects this edge case and aborts proof creation. No explicit conditional is needed in the circuit.

Where:
- **ak_P** — the spend validating key (shared with spend authority). `ExtractP(ak_P)` extracts its x-coordinate.
- **nk** — the nullifier deriving key (shared with nullifier integrity).
- **rivk** — the CommitIvk randomness, extracted from the full viewing key via `fvk.rivk(Scope::External)`. Note that it is derived once at key creation time and is static.
- **g_d_signed** — the diversified generator from the note recipient's address.
- **pk_d_signed** — the diversified transmission key from the note recipient's address.

**Constructions:**
- `CommitIvkChip` — handles decomposition and canonicity checking for the CommitIvk Sinsemilla commitment.
- `SinsemillaChip` — the same instance used for lookup tables is reused for CommitIvk.

## 6. New Note Commitment Integrity

Purpose: prove the output note's commitment is correctly constructed, with its `rho` chained from the signed note's nullifier. This creates a cryptographic link between spending the signed note and creating the output note.

```
ExtractP(NoteCommit_rcm_new(repr(g_d_new), repr(pk_d_new), 0, rho_new, psi_new)) ∈ {cmx_new, ⊥}
where rho_new = nf_signed mod q_P
```

Where:
- **rcm_new**: the output note commitment trapdoor, a scalar derived from `rseed_new` and `rho_new`. Blinds the commitment.
- **repr(g_d_new)**: the diversified base point from the output note recipient's address.
- **repr(pk_d_new)**: the diversified transmission key from the output note recipient's address.
- **0**: the note value is hardcoded to zero (same as the signed note).
- **rho_new**: set to `nf_signed` — the nullifier derived in condition 2. This is enforced in-circuit by reusing the same cell: `rho_new = nf_signed.inner().clone()`. Since `nf_signed` is already a Pallas base field element (output of `ExtractP`), it is already reduced mod `q_P`, so `mod q_P` is a no-op.
- **psi_new**: pseudorandom field element derived from `rseed_new` and `rho_new`.
- **cmx_new**: the public input. `ExtractP` extracts the x-coordinate of the commitment point. The verifier uses this to include the output note in the vote chain's commitment tree.

**Chain from condition 2**: The `nf_signed` cell computed in condition 2 (nullifier integrity) is reused directly as `rho_new`. Since that cell is also constrained to the `NF_SIGNED` public input, the chain is: `nf_signed` (public) = `DeriveNullifier(nk, rho_signed, psi_signed, cm_signed)` = `rho_new` (input to output NoteCommit).

**The ⊥ case**: Occurs when the commitment point is the identity (cryptographically negligible). Handled identically to the Orchard spec — the `NoteCommit` gadget uses incomplete addition which naturally produces ⊥ for degenerate inputs.

**Constructions:**
- `SinsemillaChip` (second instance) — a separate Sinsemilla configuration using `advices[5..]` for the output note's NoteCommit, avoiding gate conflicts with the signed note's Sinsemilla instance.
- `NoteCommitChip` (second instance) — configured with the second Sinsemilla config for decomposition/canonicity checking.

## 7. Gov Commitment Integrity

Purpose: prove that the governance commitment (a public input) is correctly derived from the output note's voting hotkey address, the total voting weight, the vote round identifier, a blinding factor, and the proposal authority bitmask. This binds the delegated weight, voting hotkey, and authority scope into a single public commitment that ZKP #2 (vote proof) can open.

```
gov_comm = Poseidon(g_d_new_x, pk_d_new_x, v_total, vote_round_id, gov_comm_rand, MAX_PROPOSAL_AUTHORITY)
```

Where:
- **g_d_new_x**: the x-coordinate of the output note's diversified generator (`ExtractP(g_d_new)`). Reuses the same ECC point already witnessed in condition 6.
- **pk_d_new_x**: the x-coordinate of the output note's diversified transmission key (`ExtractP(pk_d_new)`). Reuses the same ECC point already witnessed in condition 6.
- **v_total**: the sum `v_1 + v_2 + v_3 + v_4`, computed in-circuit via three `AddChip` additions. Each `v_i` is a free private witness (Pallas base field element representing a note value in zatoshi). The binding to actual note commitments arrives with condition 9 (Old Note Commitment Integrity).
- **vote_round_id**: the vote round identifier — reuses the same cell witnessed in condition 3 (rho binding).
- **gov_comm_rand**: a random blinding factor. Prevents observers from brute-forcing the address or weight from the public `gov_comm`.
- **MAX_PROPOSAL_AUTHORITY**: `2^16 - 1 = 65535`. A 16-bit bitmask where each bit authorizes voting on the corresponding proposal (proposal ID = bit index from LSB). Full authority means all 16 proposals are authorized. Assigned via `assign_advice_from_constant` so the value is baked into the verification key — a malicious prover cannot substitute a different authority value.

**Why 6 inputs?** The spec defines 5 semantic fields: `(vpk, v_total, vote_round_id, MAX_PROPOSAL_AUTHORITY, gov_comm_rand)`. Because `vpk` is a diversified address tuple `(g_d_new, pk_d_new)` represented as two x-coordinates, the Poseidon input naturally expands to 6 elements. This also avoids a `ConstantLength<5>` synthesis issue (the Pow5Chip's partial-round layout fails during real proving with odd-length inputs at rate 2). Both address components are explicitly bound, and `MAX_PROPOSAL_AUTHORITY` occupies its own dedicated slot.

**Constraint:** The circuit computes `derived_gov_comm = Poseidon(g_d_new_x, pk_d_new_x, v_total, vote_round_id, gov_comm_rand, MAX_PROPOSAL_AUTHORITY)` and enforces strict equality with the `gov_comm` cell witnessed in condition 3 (which is itself constrained to the public input). This creates a chain: `gov_comm` (public) = `Poseidon(address, weight, round, randomness, authority)` = the same `gov_comm` hashed into `rho_signed`.

**Constructions:**
- `PoseidonChip` with `ConstantLength<6>` — same `Pow5Chip` / `P128Pow5T3` as used in conditions 2 and 3, with 6 inputs (3 absorption rounds at rate 2).
- `AddChip` — three additions to sum `v_1 + v_2 + v_3 + v_4`.

## 8. Minimum Voting Weight

Purpose: prevent dust delegations by enforcing that the total delegated value meets a minimum threshold. Without this, an attacker could create many micro-delegations to pollute the delegation set.

```
v_total >= 12,500,000 zatoshi  (0.125 ZEC)
```

**Approach:** The circuit witnesses `diff = v_total - MIN_WEIGHT`, constrains `diff + MIN_WEIGHT == v_total` via `AddChip`, and range-checks `diff` to `[0, 2^70)` using the `LookupRangeCheckConfig`.

- If `v_total >= MIN_WEIGHT`, then `diff` is a small non-negative integer that fits in 70 bits, and the range check passes.
- If `v_total < MIN_WEIGHT`, then `diff` wraps around to approximately `2^254` (field arithmetic is modular), which vastly exceeds 70 bits, and the range check fails.

**Why 70 bits?** The range check uses 7 words × 10 bits/word = 70 bits. This comfortably covers the u64 range (64 bits) of note values, with 6 bits of headroom for the 4-note sum.

**Constructions:**
- `AddChip` — constrains `diff + MIN_WEIGHT == v_total`.
- `LookupRangeCheckConfig::copy_check` — decomposes `diff` into 7 words of 10 bits each and verifies each word via a lookup table. The `strict = true` flag ensures the running sum terminates at zero (no leftover bits).

## FAQ

- "**Why is cm_signed witnessed as a Point but ak_P as a NonIdentityPoint?"** — ak_P being identity would be a degenerate key (any signature verifies). cm_signed being identity is cryptographically negligible and caught by the equality constraint with the recomputed commitment anyway.
- "What if the same proof is submitted twice?" — The nullifier nf_signed is a public input. The consuming protocol must track spent nullifiers. The circuit itself is stateless.
- **Why are `psi` and `rcm` witnessed, not derived in-circuit?**

  Both `psi` and `rcm` are derived from `rseed` using Blake2b out-of-circuit, and are then provided to the circuit as private inputs. While this means that a malicious prover could theoretically supply arbitrary values for `psi` or `rcm`, the circuit enforces integrity via its constraints:

  - `psi` is an input to both the nullifier and the note commitment, which are themselves constrained to match public inputs and to be consistent with each other.
  - `rcm` is an input to the note commitment, which must be equal to the witnessed `cm_signed`.

  **If either `psi` or `rcm` is incorrect, the recomputed commitment will not match, and the proof will fail.**
- **Why two Sinsemilla chips?** — Each `SinsemillaChip::configure` call creates its own selectors and gates. Two independent NoteCommit operations (signed note and output note) need separate chip configurations to avoid gate conflicts. The first Sinsemilla uses `advices[..5]` and the second uses `advices[5..]`, following the same pattern as the Orchard action circuit and vote circuit.
- **"Why Sinsemilla and not Pedersen?"** — Sinsemilla uses the Pallas endomorphism for 2x speedup and is purpose-built for Halo2 lookup arguments. The NoteCommit gadget from upstream Orchard uses it.

## TODO

- Better understand underlying Poseidon and AddChip constructions. Specifically, how they select columns.
- Understand Sinsemilla construction and why it well-suited for Pallas.
