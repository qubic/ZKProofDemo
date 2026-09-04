//! Qubic identity (60 base-26 chars) <-> 32-byte pubkey with K12 checksum; mirrors core getIdentity.
#![allow(dead_code)]

const RC: [u64; 12] = [
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const ROT: [[u32; 5]; 5] = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];

fn keccak_p1600_12(l: &mut [[u64; 5]; 5]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 { c[x] = l[x][0] ^ l[x][1] ^ l[x][2] ^ l[x][3] ^ l[x][4]; }
        let mut d = [0u64; 5];
        for x in 0..5 { d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1); }
        for x in 0..5 { for y in 0..5 { l[x][y] ^= d[x]; } }
        let mut b = [[0u64; 5]; 5];
        for x in 0..5 { for y in 0..5 { b[y][(2 * x + 3 * y) % 5] = l[x][y].rotate_left(ROT[x][y]); } }
        for x in 0..5 { for y in 0..5 { l[x][y] = b[x][y] ^ (!b[(x + 1) % 5][y] & b[(x + 2) % 5][y]); } }
        l[0][0] ^= rc;
    }
}

/// KangarooTwelve, single-chunk inputs only (< 8192 bytes), `out.len()` <= 168.
pub fn k12(data: &[u8], out: &mut [u8]) {
    assert!(data.len() < 8192 && out.len() <= 168);
    let rate = 168;
    let mut padded = data.to_vec();
    padded.push(0x00); // right_encode(0): empty customization
    padded.push(0x07);
    padded.resize((padded.len() + rate - 1) / rate * rate, 0);
    *padded.last_mut().unwrap() |= 0x80;
    let mut l = [[0u64; 5]; 5];
    for block in padded.chunks(rate) {
        for i in 0..rate / 8 {
            l[i % 5][i / 5] ^= u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        keccak_p1600_12(&mut l);
    }
    let mut squeezed = Vec::with_capacity(rate);
    for i in 0..rate / 8 { squeezed.extend_from_slice(&l[i % 5][i / 5].to_le_bytes()); }
    out.copy_from_slice(&squeezed[..out.len()]);
}

pub fn pubkey_to_identity(pk: &[u8; 32]) -> String {
    let mut s = String::with_capacity(60);
    for i in 0..4 {
        let mut frag = u64::from_le_bytes(pk[i * 8..i * 8 + 8].try_into().unwrap());
        for _ in 0..14 { s.push((b'A' + (frag % 26) as u8) as char); frag /= 26; }
    }
    let mut cs = [0u8; 3];
    k12(pk, &mut cs);
    let mut checksum = u32::from_le_bytes([cs[0], cs[1], cs[2], 0]) & 0x3FFFF;
    for _ in 0..4 { s.push((b'A' + (checksum % 26) as u8) as char); checksum /= 26; }
    s
}

/// Decodes and verifies the checksum. Errors are meant to stop a build/deploy.
pub fn identity_to_pubkey(id: &str) -> Result<[u8; 32], String> {
    let b = id.as_bytes();
    if b.len() != 60 || !b.iter().all(|c| c.is_ascii_uppercase()) {
        return Err(format!("identity must be 60 upper-case letters, got {:?}", id));
    }
    let mut pk = [0u8; 32];
    for i in 0..4 {
        let mut frag: u64 = 0;
        for c in b[i * 14..(i + 1) * 14].iter().rev() { frag = frag * 26 + (c - b'A') as u64; }
        pk[i * 8..i * 8 + 8].copy_from_slice(&frag.to_le_bytes());
    }
    let expect = pubkey_to_identity(&pk);
    if expect != id { return Err(format!("identity checksum mismatch: {id} (expected {expect})")); }
    Ok(pk)
}

pub fn hex32(pk: &[u8; 32]) -> String { pk.iter().map(|b| format!("{b:02x}")).collect() }

/// Reads ZKQ_ARBITRATOR_IDENTITY from config/deploy.env (no env override: one source of truth).
pub fn arbitrator_from_config(path: &str) -> Result<(String, [u8; 32]), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let line = text.lines().map(str::trim)
        .find(|l| l.starts_with("ZKQ_ARBITRATOR_IDENTITY="))
        .ok_or_else(|| format!("ZKQ_ARBITRATOR_IDENTITY missing in {path}"))?;
    let id = line["ZKQ_ARBITRATOR_IDENTITY=".len()..].split('#').next().unwrap().trim().to_string();
    let pk = identity_to_pubkey(&id)?;
    Ok((id, pk))
}
