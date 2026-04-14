// @generated — do not edit manually
#![allow(clippy::all, unused_imports)]
use alloy_genesis::{ChainConfig, Genesis, GenesisAccount};
use alloy_primitives::{address, b256, Address, Bloom, Bytes, U256};
use reth_chainspec::{
    BaseFeeParams, BaseFeeParamsKind, ChainHardforks, ChainSpec, EthereumHardfork, ForkCondition,
    Hardfork,
};
use reth_primitives_traits::Header;
use reth_primitives_traits::SealedHeader;
use std::collections::BTreeMap;

pub fn fluent_default_chain_hardforks(osaka_fork: ForkCondition) -> ChainHardforks {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::SpuriousDragon.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Constantinople.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Petersburg.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                activation_block_number: 0,
                fork_block: None,
                total_difficulty: U256::ZERO,
            },
        ),
        (EthereumHardfork::Shanghai.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Cancun.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Prague.boxed(), ForkCondition::Timestamp(0)),
        (EthereumHardfork::Osaka.boxed(), osaka_fork),
    ])
}
#[cfg(feature = "mainnet")]
mod mainnet_genesis {
    use super::*;

    pub const ALLOC_LEN: usize = 31;

    pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {
        [
            (
                address!("0000000000000000000000000000000000000001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000002"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000002.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000003"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000003.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000004"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000004.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000a"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000a.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000b"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000b.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000c"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000c.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000d"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000d.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000e"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000e.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000f"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000f.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000010"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000010.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000011"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000011.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000100"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000100.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520010"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520010.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520fee"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520fee.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000f90827f1c53a10cb7a02335b175320002935"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000f90827f1c53a10cb7a02335b175320002935.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("3fab184622dc19b6109349b94811493bf2a45362"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: None,
                    nonce: Some(1u64),
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("482582979c9125abab5a06f0e196e8f4015bf77a"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13,
                        224, 182, 179, 167, 100, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("4e59b44847b379578588920ca78fbf26c0b4956c"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_4e59b44847b379578588920ca78fbf26c0b4956c.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("b58a6bdeb3387c87d55b7bae800f3c816f35dc34"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        124, 230, 108, 80, 226, 132, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
        ]
    }

    pub fn genesis() -> Genesis {
        let alloc: BTreeMap<Address, GenesisAccount> = genesis_alloc().into_iter().collect();

        let config = ChainConfig {
            chain_id: 25363u64,
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
            osaka_time: Some(0u64),
            terminal_total_difficulty_passed: false,
            ..Default::default()
        };

        Genesis {
            config,
            nonce: 0u64,
            timestamp: 1773672780u64,
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
            state_root: b256!("88388cf21f4e342fa9615b3b6a76361625fefd3e739f59de2860b8d8b667d5d9"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 0u64,
            gas_limit: 100000000u64,
            gas_used: 0u64,
            timestamp: 1773672780u64,
            extra_data: Bytes::default(),
            mix_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
            nonce: 0x0000000000000000u64.into(),
            base_fee_per_gas: Some(1000000000u64),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            blob_gas_used: Some(0u64),
            excess_blob_gas: Some(0u64),
            parent_beacon_block_root: Some(b256!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            requests_hash: Some(b256!(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
        }
    }

    pub fn chainspec() -> ChainSpec {
        let gen = genesis();
        let hardforks = fluent_default_chain_hardforks(ForkCondition::Timestamp(0));
        ChainSpec {
            chain: reth_chainspec::Chain::from(25363u64),
            genesis_header: SealedHeader::new_unhashed(genesis_header()),
            genesis: gen,
            paris_block_and_final_difficulty: Some((0, U256::ZERO)),
            hardforks,
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            deposit_contract: None,
            ..Default::default()
        }
    }
} // mod mainnet_genesis

#[cfg(feature = "mainnet")]
pub use mainnet_genesis::*;

#[cfg(feature = "testnet")]
mod testnet_genesis {
    use super::*;

    pub const ALLOC_LEN: usize = 31;

    pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {
        [
            (
                address!("0000000000000000000000000000000000000001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000002"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000002.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000003"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000003.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000004"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000004.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000a"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000a.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000b"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000b.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000c"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000c.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000d"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000d.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000e"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000e.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000f"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000f.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000010"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000010.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000011"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000011.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000005202"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000005202.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000f90827f1c53a10cb7a02335b175320002935"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000f90827f1c53a10cb7a02335b175320002935.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("33a831e42b24d19bf57df73682b9a3780a0435ba"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("390a4cedbb65be7511d9e1a35b115376f39dbdf3"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("52206e61746976650000000000000000ac9650d8"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_52206e61746976650000000000000000ac9650d8.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("b72988b6ddc94e577e98c5565e0e11e688537e73"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("c1202e7d42655f23097476f6d48006fe56d38d4f"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("e92c16763ba7f73a2218a5416aaa493a1f038bef"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
        ]
    }

    pub fn genesis() -> Genesis {
        let alloc: BTreeMap<Address, GenesisAccount> = genesis_alloc().into_iter().collect();

        let config = ChainConfig {
            chain_id: 20994u64,
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
            prague_time: None,
            osaka_time: Some(999999999999u64),
            terminal_total_difficulty_passed: false,
            ..Default::default()
        };

        Genesis {
            config,
            nonce: 0u64,
            timestamp: 1687223762u64,
            gas_limit: 30000000u64,
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
            state_root: b256!("ae371f85d48ef3213ceb5739ec3b3a4f9c3cbfcbfd83dad8c83a4f53e862644a"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 0u64,
            gas_limit: 30000000u64,
            gas_used: 0u64,
            timestamp: 1687223762u64,
            extra_data: Bytes::default(),
            mix_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
            nonce: 0x0000000000000000u64.into(),
            base_fee_per_gas: Some(1000000000u64),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            blob_gas_used: Some(0u64),
            excess_blob_gas: Some(0u64),
            parent_beacon_block_root: Some(b256!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            requests_hash: Some(b256!(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
        }
    }

    pub fn chainspec() -> ChainSpec {
        let gen = genesis();
        let hardforks = fluent_default_chain_hardforks(ForkCondition::Block(21300000));
        ChainSpec {
            chain: reth_chainspec::Chain::from(20994u64),
            genesis_header: SealedHeader::new_unhashed(genesis_header()),
            genesis: gen,
            paris_block_and_final_difficulty: Some((0, U256::ZERO)),
            hardforks,
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            deposit_contract: None,
            ..Default::default()
        }
    }
} // mod testnet_genesis

#[cfg(feature = "testnet")]
pub use testnet_genesis::*;

#[cfg(feature = "devnet")]
mod devnet_genesis {
    use super::*;

    pub const ALLOC_LEN: usize = 31;

    pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {
        [
            (
                address!("0000000000000000000000000000000000000001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000002"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000002.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000003"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000003.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000004"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000004.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000a"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000a.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000b"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000b.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000c"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000c.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000d"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000d.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000e"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000e.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("000000000000000000000000000000000000000f"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_000000000000000000000000000000000000000f.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000010"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000010.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000011"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000011.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000000100"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000000100.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520001"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520001.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520005"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520005.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520006"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520006.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520007"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520007.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520008"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520008.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520009"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520009.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520010"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520010.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520011"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520011.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000000000000000000000000000000000520fee"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000000000000000000000000000000000520fee.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("0000f90827f1c53a10cb7a02335b175320002935"),
                GenesisAccount {
                    balance: U256::ZERO,
                    code: Some(Bytes::from_static(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/src/fluent_genesis_bin/code_0000f90827f1c53a10cb7a02335b175320002935.bin"
                    )))),
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("33a831e42b24d19bf57df73682b9a3780a0435ba"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("390a4cedbb65be7511d9e1a35b115376f39dbdf3"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
            (
                address!("b72988b6ddc94e577e98c5565e0e11e688537e73"),
                GenesisAccount {
                    balance: U256::from_be_bytes([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 159, 44, 156,
                        208, 70, 116, 237, 234, 64, 0, 0, 0,
                    ]),
                    code: None,
                    nonce: None,
                    storage: None,
                    private_key: None,
                },
            ),
        ]
    }

    pub fn genesis() -> Genesis {
        let alloc: BTreeMap<Address, GenesisAccount> = genesis_alloc().into_iter().collect();

        let config = ChainConfig {
            chain_id: 20993u64,
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
            timestamp: 1773080086u64,
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
            state_root: b256!("d733087d118b1f04478eae870f58f7fd7ad69cb141416504e316b95ee478f215"),
            transactions_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            receipts_root: b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            ),
            logs_bloom: Bloom::ZERO,
            difficulty: U256::ZERO,
            number: 0u64,
            gas_limit: 100000000u64,
            gas_used: 0u64,
            timestamp: 1773080086u64,
            extra_data: Bytes::default(),
            mix_hash: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
            nonce: 0x0000000000000000u64.into(),
            base_fee_per_gas: Some(1000000000u64),
            withdrawals_root: Some(b256!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
            blob_gas_used: Some(0u64),
            excess_blob_gas: Some(0u64),
            parent_beacon_block_root: Some(b256!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            requests_hash: Some(b256!(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
        }
    }

    pub fn chainspec() -> ChainSpec {
        let gen = genesis();
        let hardforks = fluent_default_chain_hardforks(ForkCondition::Block(0));
        ChainSpec {
            chain: reth_chainspec::Chain::from(20993u64),
            genesis_header: SealedHeader::new_unhashed(genesis_header()),
            genesis: gen,
            paris_block_and_final_difficulty: Some((0, U256::ZERO)),
            hardforks,
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            deposit_contract: None,
            ..Default::default()
        }
    }
} // mod devnet_genesis

#[cfg(feature = "devnet")]
pub use devnet_genesis::*;
