/*
zk-tx-verifier-rs
This is a lightweight verifier demo:
- verifies a Merkle proof for a leaf (tx hash) against a given root;
- checks a mocked "zk-proof" as a Fiat-Shamir style hash binding.
*/
use sha2::{Digest, Sha256};

fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    let out = h.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

fn hex_to32(s: &str) -> [u8;32] {
    let bytes = hex::decode(s.trim_start_matches("0x")).expect("hex");
    let mut arr = [0u8;32];
    let take = bytes.len().min(32);
    arr[32-take..].copy_from_slice(&bytes[bytes.len()-take..]);
    arr
}

fn verify_merkle(leaf: [u8;32], path: &[[u8;32]], indices: &[bool], root: [u8;32]) -> bool {
    let mut cur = leaf;
    for (i, sib) in path.iter().enumerate() {
        cur = if indices[i] { hash_concat(sib, &cur) } else { hash_concat(&cur, sib) };
    }
    cur == root
}

fn verify_mock_proof(nullifier: &str, user: &str, epoch: u64, claimed: &str, proof: &str) -> bool {
    let mut h = Sha256::new();
    h.update(nullifier.as_bytes());
    h.update(user.as_bytes());
    h.update(epoch.to_be_bytes());
    h.update(claimed.as_bytes());
    let expected = format!("{:x}", h.finalize());
    expected == proof
}

fn main() {
    // Example usage (replace with real inputs)
    let leaf = hex_to32("0x01");
    let sib = hex_to32("0x02");
    let root = hash_concat(&leaf, &sib);
    let ok_merkle = verify_merkle(leaf, &[sib], &[false], root);

    let ok_proof = verify_mock_proof("nullifier123", "0xUser", 42, "airdrop:100", "9db8f6d7d730395e6be6b0c1f148f4b1e61d8469920808a1d2a0f3b0aef5d7e8");

    println!("{{\"merkle_ok\":{},\"zk_mock_ok\":{}}}", ok_merkle, ok_proof);
}
