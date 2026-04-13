use alloy_primitives::B256;

/// 130 bytes: previousBlockHash(32) | blockHash(32) | withdrawalRoot(32)
/// | depositRoot(32) | depositCount(u16BE).
///
/// Layout matches Solidity packed encoding of `IRollupTypes.L2BlockHeader`
/// at release/v0.1.0. NOT the alloy-sol-types ABI codec (which would
/// produce 160 bytes per header due to 32-byte alignment of `uint16`).
#[cfg(test)]
pub(crate) const PACKED_HEADER_SIZE: usize = 130;

pub(crate) struct L2BlockHeader {
    pub previous_block_hash: B256,
    pub block_hash: B256,
    pub withdrawal_root: B256,
    pub deposit_root: B256,
    pub deposit_count: u16,
}

impl L2BlockHeader {
    pub(crate) fn write_packed(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.previous_block_hash.as_slice());
        out.extend_from_slice(self.block_hash.as_slice());
        out.extend_from_slice(self.withdrawal_root.as_slice());
        out.extend_from_slice(self.deposit_root.as_slice());
        out.extend_from_slice(&self.deposit_count.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_size_matches_constant() {
        let h = L2BlockHeader {
            previous_block_hash: B256::from([1u8; 32]),
            block_hash: B256::from([2u8; 32]),
            withdrawal_root: B256::from([3u8; 32]),
            deposit_root: B256::from([4u8; 32]),
            deposit_count: 0x0102,
        };
        let mut out = Vec::new();
        h.write_packed(&mut out);
        assert_eq!(out.len(), PACKED_HEADER_SIZE);
        assert_eq!(&out[0..32], &[1u8; 32]);
        assert_eq!(&out[32..64], &[2u8; 32]);
        assert_eq!(&out[64..96], &[3u8; 32]);
        assert_eq!(&out[96..128], &[4u8; 32]);
        assert_eq!(&out[128..130], &[0x01, 0x02]);
    }
}
