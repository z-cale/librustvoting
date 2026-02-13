use std::time::Instant;

use anyhow::Result;
use ff::PrimeField as _;
use pasta_curves::Fp;
use rusqlite::Connection;

use imt_tree::{build_nf_ranges, build_sentinel_tree, NullifierTree, Range};

/// Load all nullifiers from the database.
fn load_all_nullifiers(connection: &Connection) -> Result<Vec<Fp>> {
    let mut s = connection.prepare("SELECT nullifier FROM nullifiers")?;
    let rows = s.query_map([], |r| {
        let v = r.get::<_, [u8; 32]>(0)?;
        let v = Fp::from_repr(v).unwrap();
        Ok(v)
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Load all nullifiers from the database, sort them, and build the gap ranges.
pub fn list_nf_ranges(connection: &Connection) -> Result<Vec<Range>> {
    let t0 = Instant::now();
    let mut nfs = load_all_nullifiers(connection)?;
    eprintln!(
        "  DB query: {} nullifiers loaded in {:.1}s",
        nfs.len(),
        t0.elapsed().as_secs_f64()
    );

    let t1 = Instant::now();
    nfs.sort();
    eprintln!("  Sort: {:.1}s", t1.elapsed().as_secs_f64());

    let t2 = Instant::now();
    let ranges = build_nf_ranges(nfs);
    eprintln!(
        "  Build ranges: {} ranges in {:.1}s",
        ranges.len(),
        t2.elapsed().as_secs_f64()
    );

    Ok(ranges)
}

/// Build a NullifierTree from the database, merging sentinel nullifiers.
///
/// The delegation circuit's q_interval gate range-checks interval widths to
/// < 2^250. Sentinel nullifiers at k * 2^250 (k = 0..=16) partition the Pallas
/// field so that every gap range stays within this bound.
pub fn tree_from_db(connection: &Connection) -> Result<NullifierTree> {
    let nfs = load_all_nullifiers(connection)?;
    build_sentinel_tree(&nfs)
}
