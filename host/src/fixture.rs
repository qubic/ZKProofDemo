//! `ZKQFIX02` fixture: everything the guest needs for one proof (SPEC.md "Wire formats v2").

//! Layout: magic | packet 21698 | queryId u64 | queryTx | reply | commit list | revealTx (length-prefixed).

//! `to_env` writes the guest input frames positionally; order must match methods/guest/src/main.rs.
use risc0_zkvm::ExecutorEnv;
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"ZKQFIX02";
pub const NUMBER_OF_COMPUTORS: usize = 676;
pub const QUORUM: usize = 451;
pub const SIGNATURE_SIZE: usize = 64;
pub const PACKET_SIZE: usize = 2 + NUMBER_OF_COMPUTORS * 32 + SIGNATURE_SIZE;
/// Bytes covered by the arbitrator signature.
pub const PACKET_SIGNED_SIZE: usize = PACKET_SIZE - SIGNATURE_SIZE;
/// Journal: epoch u32 LE | queryId u64 LE | replyDigest 32.
pub const JOURNAL_SIZE: usize = 4 + 8 + 32;

#[derive(Debug, PartialEq, Eq)]
pub struct Fixture {
    pub computors_packet: Vec<u8>,
    pub query_id: u64,
    pub query_tx: Vec<u8>,
    pub reply: Vec<u8>,
    pub commit_txs: Vec<Vec<u8>>,
    pub reveal_tx: Vec<u8>,
}

impl Fixture {
    pub fn load(path: &Path) -> Result<Fixture, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read fixture {}: {}", path.display(), e))?;
        Self::parse(&bytes).map_err(|e| format!("malformed fixture {}: {}", path.display(), e))
    }

    pub fn parse(bytes: &[u8]) -> Result<Fixture, String> {
        let mut off = 0usize;
        let take = |off: &mut usize, n: usize| -> Result<&[u8], String> {
            let s = bytes
                .get(*off..off.checked_add(n).ok_or("length overflow")?)
                .ok_or_else(|| format!("truncated at offset {}", *off))?;
            *off += n;
            Ok(s)
        };
        let read_u32 = |off: &mut usize| -> Result<usize, String> {
            Ok(u32::from_le_bytes(take(off, 4)?.try_into().unwrap()) as usize)
        };
        let read_blob = |off: &mut usize| -> Result<Vec<u8>, String> {
            let n = read_u32(off)?;
            Ok(take(off, n)?.to_vec())
        };
        if take(&mut off, 8)? != MAGIC {
            return Err("bad magic (expected ZKQFIX02)".into());
        }
        let computors_packet = take(&mut off, PACKET_SIZE)?.to_vec();
        let query_id = u64::from_le_bytes(take(&mut off, 8)?.try_into().unwrap());
        let query_tx = read_blob(&mut off)?;
        let reply = read_blob(&mut off)?;
        let n = read_u32(&mut off)?;
        if n > bytes.len() / 4 {
            return Err(format!("commit count {n} exceeds file size"));
        }
        let mut commit_txs = Vec::with_capacity(n);
        for _ in 0..n {
            commit_txs.push(read_blob(&mut off)?);
        }
        let reveal_tx = read_blob(&mut off)?;
        if off != bytes.len() {
            return Err(format!("{} trailing bytes", bytes.len() - off));
        }
        Ok(Fixture { computors_packet, query_id, query_tx, reply, commit_txs, reveal_tx })
    }

    pub fn serialize(&self) -> Vec<u8> {
        assert_eq!(self.computors_packet.len(), PACKET_SIZE);
        let blob = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        };
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.computors_packet);
        out.extend_from_slice(&self.query_id.to_le_bytes());
        blob(&mut out, &self.query_tx);
        blob(&mut out, &self.reply);
        out.extend_from_slice(&(self.commit_txs.len() as u32).to_le_bytes());
        for tx in &self.commit_txs {
            blob(&mut out, tx);
        }
        blob(&mut out, &self.reveal_tx);
        out
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.serialize())
            .map_err(|e| format!("cannot write {}: {}", path.display(), e))
    }

    pub fn epoch(&self) -> u16 {
        u16::from_le_bytes([self.computors_packet[0], self.computors_packet[1]])
    }

    pub fn commit_count(&self) -> usize {
        self.commit_txs.len()
    }

    /// Frame 5 payload: n u32 | n x (len u32 | bytes).
    fn commits_frame(&self) -> Vec<u8> {
        let mut out = (self.commit_txs.len() as u32).to_le_bytes().to_vec();
        for tx in &self.commit_txs {
            out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            out.extend_from_slice(tx);
        }
        out
    }

    /// Writes inputs in the exact positional order the guest reads them (module doc).
    pub fn to_env(&self) -> ExecutorEnv<'static> {
        ExecutorEnv::builder()
            .write_frame(&self.computors_packet)
            .write_frame(&self.query_id.to_le_bytes())
            .write_frame(&self.query_tx)
            .write_frame(&self.reply)
            .write_frame(&self.commits_frame())
            .write_frame(&self.reveal_tx)
            .build()
            .unwrap()
    }

    /// Journal the guest must commit: epoch u32 LE | queryId u64 LE | K12(reply).
    pub fn expected_journal(&self) -> [u8; JOURNAL_SIZE] {
        let mut j = [0u8; JOURNAL_SIZE];
        j[..4].copy_from_slice(&(self.epoch() as u32).to_le_bytes());
        j[4..12].copy_from_slice(&self.query_id.to_le_bytes());
        j[12..].copy_from_slice(&crate::crypto::k12(&self.reply));
        j
    }
}

/// Decoded 44-byte journal: (epoch, queryId, replyDigest).
pub fn decode_journal(j: &[u8]) -> (u32, u64, [u8; 32]) {
    assert_eq!(j.len(), JOURNAL_SIZE, "journal must be {JOURNAL_SIZE} bytes");
    (
        u32::from_le_bytes(j[..4].try_into().unwrap()),
        u64::from_le_bytes(j[4..12].try_into().unwrap()),
        j[12..].try_into().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Fixture {
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0] = 0xe7;
        packet[1] = 0x03;
        packet[2..].iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        Fixture {
            computors_packet: packet,
            query_id: (1_000_000u64 << 31) | 5,
            query_tx: (0..150u8).collect(),
            reply: b"Hello ZK, this is Qubic!".to_vec(),
            commit_txs: vec![vec![1u8; 216], vec![], vec![2u8; 3]],
            reveal_tx: vec![9u8; 176],
        }
    }

    #[test]
    fn round_trip() {
        let fx = sample();
        let bytes = fx.serialize();
        let expected_len =
            8 + PACKET_SIZE + 8 + 4 + 150 + 4 + 24 + 4 + (4 + 216) + (4 + 0) + (4 + 3) + 4 + 176;
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(&bytes[..8], MAGIC);
        let back = Fixture::parse(&bytes).unwrap();
        assert_eq!(back, fx);
        assert_eq!(back.epoch(), 999);
        assert_eq!(back.commit_count(), 3);
    }

    #[test]
    fn malformed_rejected() {
        let bytes = sample().serialize();
        assert!(Fixture::parse(b"NOPE").is_err());
        assert!(Fixture::parse(&[]).is_err());
        let mut bad_magic = bytes.clone();
        bad_magic[7] = b'1';
        assert!(Fixture::parse(&bad_magic).unwrap_err().contains("bad magic"));
        // Truncated at every possible length.
        for n in 0..bytes.len() {
            assert!(Fixture::parse(&bytes[..n]).is_err(), "accepted truncation to {n}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Fixture::parse(&trailing).unwrap_err().contains("trailing"));
        // Huge commit count / length fields must not allocate or panic.
        let n_off = 8 + PACKET_SIZE + 8 + 4 + 150 + 4 + 24;
        let mut huge = bytes.clone();
        huge[n_off..n_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Fixture::parse(&huge).is_err());
        let mut huge_len = bytes.clone();
        huge_len[n_off + 4..n_off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Fixture::parse(&huge_len).is_err());
    }

    #[test]
    fn expected_journal_layout() {
        let fx = sample();
        let j = fx.expected_journal();
        assert_eq!(j.len(), 44);
        assert_eq!(&j[..4], &[0xe7, 0x03, 0, 0]);
        assert_eq!(&j[4..12], &fx.query_id.to_le_bytes());
        assert_eq!(&j[12..], &crate::crypto::k12(&fx.reply));
        assert_eq!(decode_journal(&j), (999, fx.query_id, crate::crypto::k12(&fx.reply)));
    }

    #[test]
    fn commits_frame_layout() {
        let fx = sample();
        let f = fx.commits_frame();
        assert_eq!(&f[..4], &3u32.to_le_bytes());
        assert_eq!(&f[4..8], &216u32.to_le_bytes());
        assert_eq!(f.len(), 4 + (4 + 216) + 4 + (4 + 3));
    }
}
