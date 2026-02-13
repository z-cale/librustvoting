//! Client-side vote commitment tree.
//!
//! [`TreeClient`] maintains a sparse local copy of the tree for witness generation.
//! It syncs from a [`TreeSyncApi`] source (the server), marks positions of interest,
//! and generates Merkle authentication paths.
//!
//! This mirrors how Zcash wallets use `ShardTree` via `WalletCommitmentTrees`:
//! the client receives all leaves (no trial decryption needed since all vote-tree
//! leaves are public), inserts them, and generates witnesses only for its own
//! marked positions.

use std::collections::BTreeSet;

use incrementalmerkletree::{Hashable, Level, Retention};
use pasta_curves::Fp;
use shardtree::{store::memory::MemoryShardStore, ShardTree};

use crate::hash::{MerkleHashVote, MAX_CHECKPOINTS, SHARD_HEIGHT, TREE_DEPTH};
use crate::path::MerklePath;
use crate::sync_api::TreeSyncApi;

// ---------------------------------------------------------------------------
// TreeClient
// ---------------------------------------------------------------------------

/// Client-side sparse vote commitment tree.
///
/// Mirrors the server tree via incremental sync. Marks specific positions for
/// witness generation:
/// - **Wallet**: marks its own VAN position (for ZKP #2)
/// - **Helper server**: marks delegated VC positions (for ZKP #3)
pub struct TreeClient {
    inner: ShardTree<
        MemoryShardStore<MerkleHashVote, u32>,
        { TREE_DEPTH as u8 },
        { SHARD_HEIGHT },
    >,
    /// Next leaf position expected (mirrors server's next_position).
    next_position: u64,
    /// Latest synced block height.
    last_synced_height: Option<u32>,
    /// Positions the client wants witnesses for.
    ///
    /// In the POC, all positions are marked during sync for simplicity.
    /// In production, only the client's own positions would be marked.
    marked_positions: BTreeSet<u64>,
}

impl TreeClient {
    /// Create an empty client tree.
    pub fn empty() -> Self {
        Self {
            inner: ShardTree::new(MemoryShardStore::empty(), MAX_CHECKPOINTS),
            next_position: 0,
            last_synced_height: None,
            marked_positions: BTreeSet::new(),
        }
    }

    /// Mark a leaf position for future witness generation.
    ///
    /// Call this to record which positions the client needs witnesses for.
    /// In the POC, all positions are marked during sync regardless, but this
    /// method is provided for API completeness and future optimization.
    pub fn mark_position(&mut self, position: u64) {
        self.marked_positions.insert(position);
    }

    /// Sync the client tree from a [`TreeSyncApi`] source.
    ///
    /// Fetches block commitments from the server (incrementally, from the last
    /// synced height) and inserts them into the local tree. Each block's leaves
    /// are checkpointed at the block's height.
    ///
    /// In the POC, all leaves are inserted with `Retention::Marked` so witnesses
    /// can be generated for any position. In production, only positions in
    /// `marked_positions` would be marked, and the rest would be ephemeral.
    pub fn sync<A: TreeSyncApi>(&mut self, api: &A) -> Result<(), A::Error> {
        let state = api.get_tree_state()?;
        let from_height = self.last_synced_height.map(|h| h + 1).unwrap_or(1);
        let to_height = state.height;

        if from_height > to_height {
            return Ok(()); // Already up to date.
        }

        let blocks = api.get_block_commitments(from_height, to_height)?;

        for block in &blocks {
            for leaf in &block.leaves {
                // POC: mark all leaves so witnesses work for any position.
                // Production: use Retention::Marked only for marked_positions.
                self.inner
                    .append(*leaf, Retention::Marked)
                    .expect("append must succeed (tree not full)");
                self.next_position += 1;
            }

            // Checkpoint after each block's leaves, mirroring the server's
            // EndBlocker snapshots.
            self.inner
                .checkpoint(block.height)
                .expect("checkpoint must succeed");
            self.last_synced_height = Some(block.height);
        }

        Ok(())
    }

    /// Generate a Merkle authentication path for the leaf at `position`,
    /// valid at the given checkpoint `anchor_height`.
    ///
    /// Returns `None` if the position or checkpoint is invalid, or if the
    /// position was not marked.
    pub fn witness(&self, position: u64, anchor_height: u32) -> Option<MerklePath> {
        let pos = incrementalmerkletree::Position::from(position);
        self.inner
            .witness_at_checkpoint_id(pos, &anchor_height)
            .ok()
            .flatten()
            .map(MerklePath::from)
    }

    /// Root at a specific checkpoint height (for anchor verification).
    ///
    /// After sync, this should match the server's root at the same height.
    pub fn root_at_height(&self, height: u32) -> Option<Fp> {
        self.inner
            .root_at_checkpoint_id(&height)
            .ok()
            .flatten()
            .map(|h| h.0)
    }

    /// Current root (at the latest synced checkpoint).
    pub fn root(&self) -> Fp {
        if let Some(id) = self.last_synced_height {
            self.inner
                .root_at_checkpoint_id(&id)
                .ok()
                .flatten()
                .map(|h| h.0)
                .unwrap_or_else(|| MerkleHashVote::empty_root(Level::from(TREE_DEPTH as u8)).0)
        } else {
            MerkleHashVote::empty_root(Level::from(TREE_DEPTH as u8)).0
        }
    }

    /// Number of leaves synced.
    pub fn size(&self) -> u64 {
        self.next_position
    }

    /// Latest synced block height.
    pub fn last_synced_height(&self) -> Option<u32> {
        self.last_synced_height
    }

    /// Whether the given position has been marked for witness generation.
    pub fn is_marked(&self, position: u64) -> bool {
        self.marked_positions.contains(&position)
    }
}
