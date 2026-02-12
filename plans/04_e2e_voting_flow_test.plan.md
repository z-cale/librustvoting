---
name: E2E voting flow test
overview: "Create an end-to-end integration test that exercises the full voting flow: create session, delegate vote (ZKP #1 with real RedPallas sig), cast vote (ZKP #2 mocked), reveal share (ZKP #3 mocked), and query the final tally. All cryptographic proofs for ZKP #2 and #3 are mocked via pre-generated fixture bytes."
todos:
  - id: add-helpers
    content: Add `makeCastVotePayload` and `makeRevealSharePayload` builder functions to `sdk/tests/api/src/helpers.ts`
    status: pending
  - id: create-test
    content: "Create `sdk/tests/api/src/voting-flow.test.ts` with the full E2E flow: create session -> delegate -> cast vote -> reveal share -> verify tally"
    status: pending
  - id: verify-run
    content: Run the test suite to confirm the new test passes against a running chain
    status: pending
isProject: false
---

# End-to-End Voting Flow Integration Test

## Context

The chain already has:

- ZKP verification **mocked by default** (development mode) -- `MockVerifier` in [sdk/crypto/zkp/verify.go](sdk/crypto/zkp/verify.go) returns nil for `VerifyVoteCommitment` and `VerifyVoteShare`
- REST endpoints for all 4 message types in [sdk/api/handler.go](sdk/api/handler.go)
- Query endpoints for commitment tree state and tally in [sdk/api/query_handler.go](sdk/api/query_handler.go)
- Existing test patterns in [sdk/tests/api/src/delegation.test.ts](sdk/tests/api/src/delegation.test.ts) and [sdk/tests/api/src/helpers.ts](sdk/tests/api/src/helpers.ts)

Since ZKP #2 and #3 verification is already mocked on the chain side, the test only needs to send structurally valid payloads with mock proof bytes. No separate fixture generation is required for those circuits.

## Test Flow (single describe block in new file)

```
1. MsgCreateVotingSession  -- create a round, get roundId
2. Wait 1 block
3. MsgDelegateVote          -- delegate with real RedPallas sig + Halo2 toy proof (ZKP #1)
4. Wait 1 block             -- EndBlocker computes tree root
5. GET /commitment-tree/latest -- get anchor height for ZKP #2
6. MsgCastVote              -- cast vote with mock proof (ZKP #2)
7. Wait 1 block             -- EndBlocker computes updated tree root
8. GET /commitment-tree/latest -- get updated anchor height for ZKP #3
9. MsgRevealShare            -- reveal share with mock proof (ZKP #3)
10. Wait 1 block
11. GET /tally/{round_id}/{proposal_id} -- verify accumulated tally
```

## File Changes

### 1. New test file: `sdk/tests/api/src/voting-flow.test.ts`

A single `describe("E2E Voting Flow")` with a sequential `beforeAll` that creates the session, and individual `it()` blocks for each step. Uses Vitest's sequential execution (already configured in [sdk/tests/api/vitest.config.ts](sdk/tests/api/vitest.config.ts)).

**Key design decisions:**

- The test tracks state across steps via module-level variables (roundId, anchorHeight) shared within the describe block
- `proposal_id = 0`, `vote_decision = 1` (yes), `vote_amount = 1000` (zatoshi) as the test scenario
- Mock proof bytes: `Buffer.from("mock-cast-vote-proof")` and `Buffer.from("mock-reveal-share-proof")` -- the chain's `MockVerifier` accepts any bytes
- All nullifiers use the existing `makeUniqueNullifier` pattern (auto-incrementing counter) to avoid collisions with other tests

### 2. Add helpers to `sdk/tests/api/src/helpers.ts`

Add two new payload builder functions following the existing `makeDelegateVotePayload` pattern:

`**makeCastVotePayload(roundId, anchorHeight)**` -- builds a valid `MsgCastVote` JSON body:

```typescript
{
  van_nullifier: toBase64(makeUniqueNullifier()),
  vote_authority_note_new: toBase64(makeUniqueNullifier()),
  vote_commitment: toBase64(makeUniqueNullifier()),
  proposal_id: 0,
  proof: toBase64(Buffer.from("mock-cast-vote-proof")),
  vote_round_id: toBase64(roundId),
  vote_comm_tree_anchor_height: anchorHeight,
}
```

`**makeRevealSharePayload(roundId, anchorHeight, opts?)**` -- builds a valid `MsgRevealShare` JSON body:

```typescript
{
  share_nullifier: toBase64(makeUniqueNullifier()),
  vote_amount: opts?.voteAmount ?? 1000,
  proposal_id: opts?.proposalId ?? 0,
  vote_decision: opts?.voteDecision ?? 1,
  proof: toBase64(Buffer.from("mock-reveal-share-proof")),
  vote_round_id: toBase64(roundId),
  vote_comm_tree_anchor_height: anchorHeight,
}
```

### 3. Wire format -- JSON field names

The JSON field names must exactly match the protobuf snake_case field names from [sdk/proto/zvote/v1/tx.proto](sdk/proto/zvote/v1/tx.proto):

- **MsgCastVote**: `van_nullifier`, `vote_authority_note_new`, `vote_commitment`, `proposal_id`, `proof`, `vote_round_id`, `vote_comm_tree_anchor_height`
- **MsgRevealShare**: `share_nullifier`, `vote_amount`, `proposal_id`, `vote_decision`, `proof`, `vote_round_id`, `vote_comm_tree_anchor_height`

### 4. Commitment tree anchor

After delegation succeeds and one block passes, query `GET /zally/v1/commitment-tree/latest` to get the `CommitmentTreeState.height` value. This becomes `vote_comm_tree_anchor_height` for MsgCastVote and MsgRevealShare. The tree root at that height is stored by the EndBlocker in [sdk/x/vote/module.go](sdk/x/vote/module.go).

## Assertions

- Each transaction returns `code: 0` (accepted)
- Tally query returns `{ tally: { "1": 1000 } }` -- decision 1 accumulated 1000 zatoshi for proposal 0
- Negative path: optional follow-up tests for duplicate nullifier rejection on CastVote and RevealShare

## No changes needed on the chain side

The chain's `MockVerifier` already accepts any proof bytes for ZKP #2 and #3 in development mode. The test just needs to send structurally valid payloads.