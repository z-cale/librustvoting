//! Merkle authentication path for the vote commitment tree.

use incrementalmerkletree::Hashable;
use pasta_curves::Fp;

use crate::anchor::Anchor;
use crate::hash::{MerkleHashVote, TREE_DEPTH};

// ---------------------------------------------------------------------------
// MerklePath
// ---------------------------------------------------------------------------

/// Merkle authentication path from a leaf to the tree root.
///
/// Used by ZKP #2 (VAN membership) and ZKP #3 (VC membership).
#[derive(Clone, Debug)]
pub struct MerklePath {
    position: u32,
    auth_path: [MerkleHashVote; TREE_DEPTH],
}

impl From<incrementalmerkletree::MerklePath<MerkleHashVote, 32>> for MerklePath {
    fn from(path: incrementalmerkletree::MerklePath<MerkleHashVote, 32>) -> Self {
        let position: u64 = path.position().into();
        Self {
            position: position as u32,
            auth_path: path.path_elems().try_into().unwrap(),
        }
    }
}

impl MerklePath {
    /// Construct from raw parts.
    pub fn from_parts(position: u32, auth_path: [MerkleHashVote; TREE_DEPTH]) -> Self {
        Self {
            position,
            auth_path,
        }
    }

    /// Recompute the root from the given leaf and this authentication path.
    pub fn root(&self, leaf: MerkleHashVote) -> Anchor {
        self.auth_path
            .iter()
            .enumerate()
            .fold(leaf, |node, (l, sibling)| {
                let l = l as u8;
                if self.position & (1 << l) == 0 {
                    MerkleHashVote::combine(l.into(), &node, sibling)
                } else {
                    MerkleHashVote::combine(l.into(), sibling, &node)
                }
            })
            .into()
    }

    /// Verify that this path produces the expected `root` when combined with `leaf`.
    pub fn verify(&self, leaf: Fp, root: Fp) -> bool {
        let computed = self.root(MerkleHashVote::from_fp(leaf));
        computed.inner() == root
    }

    /// Leaf position in the tree.
    pub fn position(&self) -> u32 {
        self.position
    }

    /// The authentication path (sibling hashes from leaf to root).
    pub fn auth_path(&self) -> &[MerkleHashVote; TREE_DEPTH] {
        &self.auth_path
    }
}
