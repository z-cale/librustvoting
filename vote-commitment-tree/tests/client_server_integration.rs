//! Integration test: server appends (delegate + vote), client syncs incrementally,
//! witnesses verify against server roots.
//!
//! This proves:
//! - Server appends continuously and checkpoints per block
//! - Client syncs incrementally via TreeSyncApi
//! - Client-generated witnesses are valid against server roots
//! - Roots match between server and client at every synced height

use pasta_curves::Fp;
use vote_commitment_tree::{TreeClient, TreeServer, TreeSyncApi};

fn fp(x: u64) -> Fp {
    Fp::from(x)
}

/// Full lifecycle: MsgDelegateVote → client sync → MsgCastVote → client sync → witnesses verify.
///
/// Corresponds to the plan's integration test steps:
///  1. Create TreeServer (empty)
///  2. Simulate MsgDelegateVote: server.append(van_alice), server.checkpoint(1)
///  3. Client syncs block 1, marks position 0, generates witness at height 1
///  4. Simulate MsgCastVote: server.append_two(new_van_alice, vc_alice), server.checkpoint(2)
///  5. Client syncs block 2, marks VC position, generates witness at height 2
///  6. All witnesses verify against the server's roots
#[test]
fn server_append_client_sync_witness_roundtrip() {
    // ---------------------------------------------------------------
    // 1. Create TreeServer (empty)
    // ---------------------------------------------------------------
    let mut server = TreeServer::empty();
    let mut client = TreeClient::empty();

    // ---------------------------------------------------------------
    // 2. Simulate MsgDelegateVote: append VAN for Alice
    //    EndBlocker: checkpoint at height 1
    // ---------------------------------------------------------------
    let van_alice = fp(100);
    let van_idx = server.append(van_alice);
    assert_eq!(van_idx, 0, "first leaf should be at index 0");
    server.checkpoint(1);

    // ---------------------------------------------------------------
    // 3. Client syncs from server (gets block 1)
    // ---------------------------------------------------------------
    client.sync(&server).unwrap();

    assert_eq!(client.size(), 1, "client should have 1 leaf after sync");
    assert_eq!(
        client.last_synced_height(),
        Some(1),
        "client should be at height 1"
    );

    // Verify roots match between server and client at height 1.
    let server_root_1 = server.root_at_height(1).expect("server has root at height 1");
    let client_root_1 = client.root_at_height(1).expect("client has root at height 1");
    assert_eq!(
        server_root_1, client_root_1,
        "server and client roots must match at height 1"
    );

    // Client marks position 0 (Alice's VAN — she needs a witness for ZKP #2).
    client.mark_position(0);

    // Client generates witness at anchor height 1.
    let witness_1 = client
        .witness(0, 1)
        .expect("witness for position 0 at height 1");

    // Assert: witness verifies against server's root at height 1.
    assert!(
        witness_1.verify(van_alice, server_root_1),
        "witness for VAN at position 0 must verify against server root at height 1"
    );

    // Also verify via the server's own path (sanity check).
    let server_path_1 = server.path(0, 1).expect("server has path for position 0");
    assert!(server_path_1.verify(van_alice, server_root_1));

    // ---------------------------------------------------------------
    // 4. Simulate MsgCastVote: append new VAN + VC for Alice
    //    EndBlocker: checkpoint at height 2
    // ---------------------------------------------------------------
    let new_van_alice = fp(200); // New VAN (decremented proposal authority)
    let vc_alice = fp(300); // Vote commitment
    let cast_idx = server.append_two(new_van_alice, vc_alice);
    assert_eq!(cast_idx, 1, "MsgCastVote first leaf at index 1");
    assert_eq!(server.size(), 3, "server has 3 leaves total");
    server.checkpoint(2);

    // ---------------------------------------------------------------
    // 5. Client syncs block 2 (incremental — only new data)
    // ---------------------------------------------------------------
    client.sync(&server).unwrap();

    assert_eq!(client.size(), 3, "client should have 3 leaves after second sync");
    assert_eq!(
        client.last_synced_height(),
        Some(2),
        "client should be at height 2"
    );

    // Verify roots match at height 2.
    let server_root_2 = server.root_at_height(2).expect("server has root at height 2");
    let client_root_2 = client.root_at_height(2).expect("client has root at height 2");
    assert_eq!(
        server_root_2, client_root_2,
        "server and client roots must match at height 2"
    );

    // Root at height 1 is still accessible and unchanged.
    assert_eq!(
        client.root_at_height(1).unwrap(),
        server_root_1,
        "historical root at height 1 must be preserved"
    );

    // Roots at different heights must differ (tree grew).
    assert_ne!(
        server_root_1, server_root_2,
        "root should change after appending more leaves"
    );

    // ---------------------------------------------------------------
    // 6. Client marks VC position and generates witness at height 2
    //    (Helper server needs this for ZKP #3)
    // ---------------------------------------------------------------
    client.mark_position(2); // VC is at position 2

    let witness_vc = client
        .witness(2, 2)
        .expect("witness for VC at position 2, anchor height 2");

    assert!(
        witness_vc.verify(vc_alice, server_root_2),
        "witness for VC must verify against server root at height 2"
    );

    // Also verify the new VAN witness (position 1) at height 2.
    let witness_new_van = client
        .witness(1, 2)
        .expect("witness for new VAN at position 1, anchor height 2");
    assert!(
        witness_new_van.verify(new_van_alice, server_root_2),
        "witness for new VAN must verify against server root at height 2"
    );

    // Verify server produces the same witnesses.
    let server_path_vc = server.path(2, 2).expect("server path for VC");
    assert!(server_path_vc.verify(vc_alice, server_root_2));
}

/// Test that the original VAN witness (position 0) still verifies at its
/// original anchor (height 1) even after the tree has grown.
#[test]
fn historical_witness_survives_growth() {
    let mut server = TreeServer::empty();

    // Block 1: one VAN.
    server.append(fp(1));
    server.checkpoint(1);
    let root_1 = server.root_at_height(1).unwrap();

    // Block 2: two more leaves.
    server.append_two(fp(2), fp(3));
    server.checkpoint(2);

    // Block 3: one more.
    server.append(fp(4));
    server.checkpoint(3);

    // Client syncs the full history.
    let mut client = TreeClient::empty();
    client.sync(&server).unwrap();
    assert_eq!(client.size(), 4);

    // Witness at height 1 (before growth) still verifies.
    let witness = client.witness(0, 1).expect("historical witness at height 1");
    assert!(
        witness.verify(fp(1), root_1),
        "historical witness must verify against the original anchor"
    );
}

/// Test the TreeSyncApi contract directly: get_tree_state, get_block_commitments,
/// and get_root_at_height return consistent data.
#[test]
fn sync_api_consistency() {
    let mut server = TreeServer::empty();

    // Append across multiple blocks.
    for height in 1..=5u32 {
        for i in 0..height {
            server.append(fp((height * 100 + i) as u64));
        }
        server.checkpoint(height);
    }

    // get_tree_state reflects the tip.
    let state = server.get_tree_state().unwrap();
    assert_eq!(state.height, 5);
    assert_eq!(state.next_index, 1 + 2 + 3 + 4 + 5); // 15 total leaves
    assert_eq!(state.root, server.root());

    // get_block_commitments for a subrange.
    let blocks = server.get_block_commitments(2, 4).unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].height, 2);
    assert_eq!(blocks[1].height, 3);
    assert_eq!(blocks[2].height, 4);
    assert_eq!(blocks[0].leaves.len(), 2);
    assert_eq!(blocks[1].leaves.len(), 3);
    assert_eq!(blocks[2].leaves.len(), 4);

    // get_root_at_height for each block matches server.root_at_height.
    for height in 1..=5u32 {
        let api_root = server.get_root_at_height(height).unwrap();
        let direct_root = server.root_at_height(height);
        assert_eq!(api_root, direct_root);
    }
}

/// Test that a fresh client can sync all blocks at once (full sync).
#[test]
fn full_sync_from_genesis() {
    let mut server = TreeServer::empty();

    // 10 blocks, 2 leaves each.
    for h in 1..=10u32 {
        server.append(fp(h as u64 * 10));
        server.append(fp(h as u64 * 10 + 1));
        server.checkpoint(h);
    }

    let mut client = TreeClient::empty();
    client.sync(&server).unwrap();

    assert_eq!(client.size(), 20);
    assert_eq!(client.last_synced_height(), Some(10));

    // Every checkpoint root matches.
    for h in 1..=10u32 {
        assert_eq!(
            client.root_at_height(h),
            server.root_at_height(h),
            "root mismatch at height {}",
            h
        );
    }

    // Witnesses for a few positions verify.
    for pos in [0u64, 5, 10, 19] {
        let leaf_val = if pos % 2 == 0 {
            fp((pos / 2 + 1) * 10)
        } else {
            fp((pos / 2 + 1) * 10 + 1)
        };
        let _anchor_h = (pos / 2 + 1) as u32; // Block that contains this leaf.
        let witness = client
            .witness(pos, 10) // witness at latest anchor
            .unwrap_or_else(|| panic!("witness for position {}", pos));
        assert!(
            witness.verify(leaf_val, server.root_at_height(10).unwrap()),
            "witness for position {} must verify",
            pos
        );
    }
}

/// Test idempotent sync — calling sync when already up-to-date is a no-op.
#[test]
fn sync_idempotent_when_up_to_date() {
    let mut server = TreeServer::empty();
    server.append(fp(1));
    server.checkpoint(1);

    let mut client = TreeClient::empty();
    client.sync(&server).unwrap();
    assert_eq!(client.size(), 1);

    // Sync again with no new data.
    client.sync(&server).unwrap();
    assert_eq!(client.size(), 1);
    assert_eq!(client.last_synced_height(), Some(1));
}
