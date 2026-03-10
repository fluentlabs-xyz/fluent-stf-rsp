// @generated — do not edit manually
#![allow(clippy::all)]
use alloy_primitives::{address, b256, U256, Bytes, Address, Bloom};
use alloy_genesis::{Genesis, GenesisAccount, ChainConfig};
use reth_primitives_traits::Header;
use std::collections::BTreeMap;

pub const ALLOC_LEN: usize = 30;

pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {
    [
        (
            address!("0000000000000000000000000000000000000001"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000001.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000002"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000002.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000003"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000003.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000004"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000004.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000005"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000005.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000006"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000006.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000007"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000007.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000008"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000008.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000009"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000009.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000a"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000a.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000b"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000b.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000c"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000c.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000d"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000d.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000e"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000e.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("000000000000000000000000000000000000000f"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000f.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000010"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000010.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000011"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000011.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000000100"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000100.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520001"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520001.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520005"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520005.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520006"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520006.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520007"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520007.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520008"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520008.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520009"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520009.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520010"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520010.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000000000000000000000000000000000520fee"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520fee.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("0000f90827f1c53a10cb7a02335b175320002935"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
                code: Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/code_0000f90827f1c53a10cb7a02335b175320002935.bin")))),
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("33a831e42b24d19bf57df73682b9a3780a0435ba"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,159,44,156,208,70,116,237,234,64,0,0,0]),
                code: None,
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("390a4cedbb65be7511d9e1a35b115376f39dbdf3"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,159,44,156,208,70,116,237,234,64,0,0,0]),
                code: None,
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
        (
            address!("b72988b6ddc94e577e98c5565e0e11e688537e73"),
            GenesisAccount {
                balance: U256::from_be_bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,159,44,156,208,70,116,237,234,64,0,0,0]),
                code: None,
                nonce: None,
                storage: None,
                private_key: None,
            }
        ),
    ]
}

pub fn genesis() -> Genesis {
    let alloc: BTreeMap<Address, GenesisAccount> =
        genesis_alloc().into_iter().collect();

    let config = ChainConfig {
        chain_id: 1337u64,
        homestead_block: Some(0u64),
        dao_fork_block: Some(0u64),
        dao_fork_support: true,
        eip150_block: Some(0u64),
        eip155_block: Some(0u64),
        eip158_block: Some(0u64),
        byzantium_block: Some(0u64),
        constantinople_block: Some(0u64),
        petersburg_block: Some(0u64),
        istanbul_block: Some(0u64),
        muir_glacier_block: Some(0u64),
        berlin_block: Some(0u64),
        london_block: Some(0u64),
        arrow_glacier_block: Some(0u64),
        gray_glacier_block: Some(0u64),
        merge_netsplit_block: Some(0u64),
        shanghai_time: Some(0u64),
        cancun_time: Some(0u64),
        prague_time: Some(0u64),
        osaka_time: Some(999999999999u64),
        terminal_total_difficulty_passed: false,
        ..Default::default()
    };

    Genesis {
        config,
        nonce: 0u64,
        timestamp: 1773063302u64,
        gas_limit: 100000000u64,
        number: Some(0u64),
        difficulty: U256::ZERO,
        mix_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
        coinbase: address!("0000000000000000000000000000000000000000"),
        extra_data: Bytes::default(),
        alloc,
        ..Default::default()
    }
}

pub fn genesis_header() -> Header {
    Header {
        parent_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
        ommers_hash: b256!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
        beneficiary: address!("0000000000000000000000000000000000000000"),
        state_root: b256!("aa8839f82fc8bbab1aa68fa09a6c95469f0ef36488d2edb0e4d1abf849873903"),
        transactions_root: b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
        receipts_root: b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
        logs_bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        number: 0u64,
        gas_limit: 100000000u64,
        gas_used: 0u64,
        timestamp: 1773063302u64,
        extra_data: Bytes::default(),
        mix_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
        nonce: 0x0000000000000000u64.into(),
        base_fee_per_gas: Some(1000000000u64),
        withdrawals_root: Some(b256!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")),
        blob_gas_used: Some(0u64),
        excess_blob_gas: Some(0u64),
        parent_beacon_block_root: Some(b256!("0000000000000000000000000000000000000000000000000000000000000000")),
        requests_hash: Some(b256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
    }
}
