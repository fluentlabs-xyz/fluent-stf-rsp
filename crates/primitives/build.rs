use alloy_genesis::{ChainConfig, Genesis, GenesisAccount};
use alloy_primitives::{Address, Bytes, U256};
use reth_chainspec::{make_genesis_header, DEV_HARDFORKS};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

// ─── helpers (unchanged) ─────────────────────────────────────────────────────

fn write_if_changed(path: &Path, content: &[u8]) {
    if let Ok(existing) = fs::read(path) {
        if existing == content {
            return;
        }
    }
    fs::write(path, content).unwrap();
}

fn write_bin_if_changed(path: &Path, bytes: &[u8]) {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return;
        }
    }
    fs::write(path, bytes).unwrap();
}

fn fmt_b256(val: &alloy_primitives::B256) -> String {
    format!("b256!(\"{}\")", hex::encode(val.as_slice()))
}

fn fmt_opt_b256(val: &Option<alloy_primitives::B256>) -> String {
    match val {
        Some(v) => format!("Some({})", fmt_b256(v)),
        None => "None".to_string(),
    }
}

fn fmt_opt_u64(val: Option<u64>) -> String {
    match val {
        Some(v) => format!("Some({v}u64)"),
        None => "None".to_string(),
    }
}

fn fmt_u256(val: &U256) -> String {
    if val.is_zero() {
        return "U256::ZERO".to_string();
    }
    let bytes = val.to_be_bytes::<32>();
    format!(
        "U256::from_be_bytes([{}])",
        bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    )
}

fn fmt_bloom(bloom: &alloy_primitives::Bloom) -> String {
    if bloom.is_zero() {
        "Bloom::ZERO".to_string()
    } else {
        let bytes = bloom.as_slice();
        format!(
            "Bloom::new([{}])",
            bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        )
    }
}

fn fmt_bytes(bytes: &Bytes) -> String {
    if bytes.is_empty() {
        "Bytes::default()".to_string()
    } else {
        format!(
            "Bytes::from_static(&[{}])",
            bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        )
    }
}

// ─── genesis file resolution ─────────────────────────────────────────────────

/// Describes one genesis source: the file path and its cargo feature gate (if any).
struct GenesisSource {
    path: PathBuf,
    /// `None` means "always included" (base).
    feature: Option<&'static str>,
}

/// Returns the ordered list of genesis sources.
/// The first entry is the **base** (always active) — it supplies `config`,
/// top-level fields, and a default alloc.
/// Subsequent entries are feature-gated overlays whose alloc is merged on top,
/// with later entries winning on duplicate addresses.
fn genesis_sources(manifest_dir: &Path) -> Vec<GenesisSource> {
    let genesis_dir = manifest_dir.join("../../bin/host/genesis");

    vec![
        GenesisSource {
            path: genesis_dir.join("genesis-v0.5.7.json"),
            feature: None,
        },
        GenesisSource {
            path: genesis_dir.join("genesis-v0.3.4-dev.json"),
            feature: Some("testnet"),
        },
        GenesisSource {
            path: genesis_dir.join("genesis-v0.5.7.json"),
            feature: Some("devnet"),
        },
    ]
}

fn is_active(source: &GenesisSource) -> bool {
    match source.feature {
        None => true,
        Some(feat) => std::env::var(format!("CARGO_FEATURE_{}", feat.to_uppercase()))
            .is_ok(),
    }
}

// ─── merged alloc helpers ────────────────────────────────────────────────────

/// Canonical address key (lowercase, no 0x, zero-padded to 40 chars).
fn canonical_addr(raw: &str) -> String {
    format!("{:0>40}", raw.trim_start_matches("0x").to_lowercase())
}

/// Merge `alloc` objects from multiple JSON values.
/// Later entries override earlier ones for the same address.
fn merge_allocs(jsons: &[Value]) -> BTreeMap<String, Value> {
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for json in jsons {
        if let Some(alloc) = json["alloc"].as_object() {
            for (addr, account) in alloc {
                merged.insert(canonical_addr(addr), account.clone());
            }
        }
    }
    merged
}

// ─── account codegen ─────────────────────────────────────────────────────────

fn emit_account(addr_clean: &str, account: &Value, bin_dir: &Path) -> String {
    let balance_hex = account["balance"].as_str().unwrap_or("0x0");
    let balance_u256 = U256::from_str_radix(balance_hex.trim_start_matches("0x"), 16).unwrap();
    let balance_bytes = balance_u256.to_be_bytes::<32>();
    let balance_lit = format!(
        "U256::from_be_bytes([{}])",
        balance_bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    );

    let nonce_lit = match account["nonce"].as_str() {
        Some(n) => {
            format!("Some({}u64)", u64::from_str_radix(n.trim_start_matches("0x"), 16).unwrap())
        }
        None => "None".to_string(),
    };

    let fname = format!("code_{addr_clean}.bin");
    let code_lit = match account["code"].as_str() {
        Some(code_hex) => {
            let code_hex = code_hex.trim_start_matches("0x");
            if code_hex.is_empty() {
                "None".to_string()
            } else {
                let bytes = hex::decode(code_hex).unwrap();
                write_bin_if_changed(&bin_dir.join(&fname), &bytes);
                format!(
                    r#"Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/{fname}"))))"#
                )
            }
        }
        None => "None".to_string(),
    };

    format!(
        r#"(
            address!("{addr_clean}"),
            GenesisAccount {{
                balance: {balance_lit},
                code: {code_lit},
                nonce: {nonce_lit},
                storage: None,
                private_key: None,
            }}
        )"#
    )
}

// ─── build Genesis object (from base JSON + merged alloc) ────────────────────

fn build_genesis_object(base_json: &Value, merged_alloc: &BTreeMap<String, Value>) -> Genesis {
    let mut alloc = BTreeMap::new();
    for (addr_clean, account) in merged_alloc {
        let address: Address = addr_clean.parse().unwrap();

        let balance_hex = account["balance"].as_str().unwrap_or("0x0");
        let balance = U256::from_str_radix(balance_hex.trim_start_matches("0x"), 16).unwrap();

        let nonce = account["nonce"]
            .as_str()
            .map(|n| u64::from_str_radix(n.trim_start_matches("0x"), 16).unwrap());

        let code = account["code"].as_str().and_then(|c| {
            let c = c.trim_start_matches("0x");
            if c.is_empty() { None } else { Some(Bytes::from(hex::decode(c).unwrap())) }
        });

        alloc.insert(
            address,
            GenesisAccount { balance, code, nonce, storage: None, private_key: None },
        );
    }

    let cfg = &base_json["config"];
    let config = ChainConfig {
        chain_id: cfg["chainId"].as_u64().unwrap_or(1337),
        homestead_block: Some(cfg["homesteadBlock"].as_u64().unwrap_or(0)),
        dao_fork_block: Some(cfg["daoForkBlock"].as_u64().unwrap_or(0)),
        dao_fork_support: cfg["daoForkSupport"].as_bool().unwrap_or(false),
        eip150_block: Some(cfg["eip150Block"].as_u64().unwrap_or(0)),
        eip155_block: Some(cfg["eip155Block"].as_u64().unwrap_or(0)),
        eip158_block: Some(cfg["eip158Block"].as_u64().unwrap_or(0)),
        byzantium_block: Some(cfg["byzantiumBlock"].as_u64().unwrap_or(0)),
        constantinople_block: Some(cfg["constantinopleBlock"].as_u64().unwrap_or(0)),
        petersburg_block: Some(cfg["petersburgBlock"].as_u64().unwrap_or(0)),
        istanbul_block: Some(cfg["istanbulBlock"].as_u64().unwrap_or(0)),
        muir_glacier_block: Some(cfg["muirGlacierBlock"].as_u64().unwrap_or(0)),
        berlin_block: Some(cfg["berlinBlock"].as_u64().unwrap_or(0)),
        london_block: Some(cfg["londonBlock"].as_u64().unwrap_or(0)),
        arrow_glacier_block: Some(cfg["arrowGlacierBlock"].as_u64().unwrap_or(0)),
        gray_glacier_block: Some(cfg["grayGlacierBlock"].as_u64().unwrap_or(0)),
        merge_netsplit_block: Some(cfg["mergeNetsplitBlock"].as_u64().unwrap_or(0)),
        shanghai_time: Some(cfg["shanghaiTime"].as_u64().unwrap_or(0)),
        cancun_time: Some(cfg["cancunTime"].as_u64().unwrap_or(0)),
        prague_time: Some(cfg["pragueTime"].as_u64().unwrap_or(0)),
        osaka_time: Some(cfg["osakaTime"].as_u64().unwrap_or(999999999999)),
        terminal_total_difficulty_passed: cfg["terminalTotalDifficultyPassed"]
            .as_bool()
            .unwrap_or(false),
        ..Default::default()
    };

    let parse_hex_u64 = |v: &Value| -> u64 {
        u64::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap()
    };

    let difficulty = U256::from_str_radix(
        base_json["difficulty"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
        16,
    )
    .unwrap();

    let mix_hash_str = format!(
        "{:0>64}",
        base_json["mixHash"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );
    let coinbase_str = format!(
        "{:0>40}",
        base_json["coinbase"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );

    let extra_data = Bytes::from(
        hex::decode(base_json["extraData"].as_str().unwrap_or("0x").trim_start_matches("0x"))
            .unwrap(),
    );

    Genesis {
        config,
        nonce: parse_hex_u64(&base_json["nonce"]),
        timestamp: parse_hex_u64(&base_json["timestamp"]),
        gas_limit: parse_hex_u64(&base_json["gasLimit"]),
        number: Some(parse_hex_u64(&base_json["number"])),
        difficulty,
        mix_hash: mix_hash_str.parse().unwrap(),
        coinbase: coinbase_str.parse().unwrap(),
        extra_data,
        alloc,
        ..Default::default()
    }
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let src_dir = manifest_dir.join("src");
    let bin_dir = src_dir.join("fluent_genesis_bin");
    fs::create_dir_all(&bin_dir).unwrap();

    // ── collect active genesis sources ───────────────────────────────────────

    let sources = genesis_sources(&manifest_dir);
    let active: Vec<&GenesisSource> = sources.iter().filter(|s| is_active(s)).collect();

    // register rerun-if-changed for ALL sources (so toggling a feature rebuilds)
    for s in &sources {
        println!("cargo:rerun-if-changed={}", s.path.display());
    }

    // ── load JSONs ───────────────────────────────────────────────────────────

    let jsons: Vec<Value> = active
        .iter()
        .map(|s| {
            let raw = fs::read_to_string(&s.path)
                .unwrap_or_else(|_| panic!("genesis file not found: {}", s.path.display()));
            serde_json::from_str(&raw)
                .unwrap_or_else(|_| panic!("failed to parse: {}", s.path.display()))
        })
        .collect();

    // base JSON is always the first one (feature: None)
    let base_json = &jsons[0];

    // ── merge allocs (later wins on duplicate address) ───────────────────────

    let merged_alloc = merge_allocs(&jsons);
    let count = merged_alloc.len();

    // ── compute header ───────────────────────────────────────────────────────

    let genesis_obj = build_genesis_object(base_json, &merged_alloc);
    let hardforks = DEV_HARDFORKS.clone();
    let header = make_genesis_header(&genesis_obj, &hardforks);

    // ── codegen ──────────────────────────────────────────────────────────────

    let mut out = String::new();

    out.push_str("// @generated — do not edit manually\n");
    out.push_str("#![allow(clippy::all)]\n");
    out.push_str("use alloy_primitives::{address, b256, U256, Bytes, Address, Bloom};\n");
    out.push_str("use alloy_genesis::{Genesis, GenesisAccount, ChainConfig};\n");
    out.push_str("use reth_primitives_traits::Header;\n");
    out.push_str("use std::collections::BTreeMap;\n\n");

    // ── alloc ────────────────────────────────────────────────────────────────

    out.push_str(&format!("pub const ALLOC_LEN: usize = {count};\n\n"));
    out.push_str("pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {\n");
    out.push_str("    [\n");

    for (addr_clean, account) in &merged_alloc {
        let entry = emit_account(addr_clean, account, &bin_dir);
        out.push_str(&format!("        {entry},\n"));
    }

    out.push_str("    ]\n}\n\n");

    // ── genesis() ────────────────────────────────────────────────────────────

    let cfg = &base_json["config"];

    let chain_id = cfg["chainId"].as_u64().unwrap_or(1337);
    let homestead = cfg["homesteadBlock"].as_u64().unwrap_or(0);
    let dao_fork_blk = cfg["daoForkBlock"].as_u64().unwrap_or(0);
    let dao_fork_sup = cfg["daoForkSupport"].as_bool().unwrap_or(false);
    let eip150 = cfg["eip150Block"].as_u64().unwrap_or(0);
    let eip155 = cfg["eip155Block"].as_u64().unwrap_or(0);
    let eip158 = cfg["eip158Block"].as_u64().unwrap_or(0);
    let byzantium = cfg["byzantiumBlock"].as_u64().unwrap_or(0);
    let constantinople = cfg["constantinopleBlock"].as_u64().unwrap_or(0);
    let petersburg = cfg["petersburgBlock"].as_u64().unwrap_or(0);
    let istanbul = cfg["istanbulBlock"].as_u64().unwrap_or(0);
    let muir_glacier = cfg["muirGlacierBlock"].as_u64().unwrap_or(0);
    let berlin = cfg["berlinBlock"].as_u64().unwrap_or(0);
    let london = cfg["londonBlock"].as_u64().unwrap_or(0);
    let arrow_glacier = cfg["arrowGlacierBlock"].as_u64().unwrap_or(0);
    let gray_glacier = cfg["grayGlacierBlock"].as_u64().unwrap_or(0);
    let merge_netsplit = cfg["mergeNetsplitBlock"].as_u64().unwrap_or(0);
    let shanghai_time = cfg["shanghaiTime"].as_u64().unwrap_or(0);
    let cancun_time = cfg["cancunTime"].as_u64().unwrap_or(0);
    let prague_time = cfg["pragueTime"].as_u64().unwrap_or(0);
    let osaka_time = cfg["osakaTime"].as_u64().unwrap_or(999999999999);
    let ttd_passed = cfg["terminalTotalDifficultyPassed"].as_bool().unwrap_or(false);

    let parse_hex_u64 = |v: &Value| -> u64 {
        u64::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap()
    };

    let timestamp = parse_hex_u64(&base_json["timestamp"]);
    let gas_limit = parse_hex_u64(&base_json["gasLimit"]);
    let nonce = parse_hex_u64(&base_json["nonce"]);
    let number = parse_hex_u64(&base_json["number"]);

    let difficulty_lit = fmt_u256(
        &U256::from_str_radix(
            base_json["difficulty"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
            16,
        )
        .unwrap(),
    );

    let mix_hash = format!(
        "{:0>64}",
        base_json["mixHash"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );
    let coinbase = format!(
        "{:0>40}",
        base_json["coinbase"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );

    let extra_data_bytes = hex::decode(
        base_json["extraData"].as_str().unwrap_or("0x").trim_start_matches("0x"),
    )
    .unwrap();
    let extra_data_lit = if extra_data_bytes.is_empty() {
        "Bytes::default()".to_string()
    } else {
        format!(
            "Bytes::from_static(&[{}])",
            extra_data_bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        )
    };

    out.push_str("pub fn genesis() -> Genesis {\n");
    out.push_str("    let alloc: BTreeMap<Address, GenesisAccount> =\n");
    out.push_str("        genesis_alloc().into_iter().collect();\n\n");
    out.push_str("    let config = ChainConfig {\n");
    out.push_str(&format!("        chain_id: {chain_id}u64,\n"));
    out.push_str(&format!("        homestead_block: Some({homestead}u64),\n"));
    out.push_str(&format!("        dao_fork_block: Some({dao_fork_blk}u64),\n"));
    out.push_str(&format!("        dao_fork_support: {dao_fork_sup},\n"));
    out.push_str(&format!("        eip150_block: Some({eip150}u64),\n"));
    out.push_str(&format!("        eip155_block: Some({eip155}u64),\n"));
    out.push_str(&format!("        eip158_block: Some({eip158}u64),\n"));
    out.push_str(&format!("        byzantium_block: Some({byzantium}u64),\n"));
    out.push_str(&format!("        constantinople_block: Some({constantinople}u64),\n"));
    out.push_str(&format!("        petersburg_block: Some({petersburg}u64),\n"));
    out.push_str(&format!("        istanbul_block: Some({istanbul}u64),\n"));
    out.push_str(&format!("        muir_glacier_block: Some({muir_glacier}u64),\n"));
    out.push_str(&format!("        berlin_block: Some({berlin}u64),\n"));
    out.push_str(&format!("        london_block: Some({london}u64),\n"));
    out.push_str(&format!("        arrow_glacier_block: Some({arrow_glacier}u64),\n"));
    out.push_str(&format!("        gray_glacier_block: Some({gray_glacier}u64),\n"));
    out.push_str(&format!("        merge_netsplit_block: Some({merge_netsplit}u64),\n"));
    out.push_str(&format!("        shanghai_time: Some({shanghai_time}u64),\n"));
    out.push_str(&format!("        cancun_time: Some({cancun_time}u64),\n"));
    out.push_str(&format!("        prague_time: Some({prague_time}u64),\n"));
    out.push_str(&format!("        osaka_time: Some({osaka_time}u64),\n"));
    out.push_str(&format!("        terminal_total_difficulty_passed: {ttd_passed},\n"));
    out.push_str("        ..Default::default()\n");
    out.push_str("    };\n\n");
    out.push_str("    Genesis {\n");
    out.push_str("        config,\n");
    out.push_str(&format!("        nonce: {nonce}u64,\n"));
    out.push_str(&format!("        timestamp: {timestamp}u64,\n"));
    out.push_str(&format!("        gas_limit: {gas_limit}u64,\n"));
    out.push_str(&format!("        number: Some({number}u64),\n"));
    out.push_str(&format!("        difficulty: {difficulty_lit},\n"));
    out.push_str(&format!("        mix_hash: b256!(\"{mix_hash}\"),\n"));
    out.push_str(&format!("        coinbase: address!(\"{coinbase}\"),\n"));
    out.push_str(&format!("        extra_data: {extra_data_lit},\n"));
    out.push_str("        alloc,\n");
    out.push_str("        ..Default::default()\n");
    out.push_str("    }\n");
    out.push_str("}\n\n");

    // ── genesis_header() ─────────────────────────────────────────────────────

    let h_parent_hash = fmt_b256(&header.parent_hash);
    let h_ommers_hash = fmt_b256(&header.ommers_hash);
    let h_beneficiary = format!("address!(\"{}\")", hex::encode(header.beneficiary.as_slice()));
    let h_state_root = fmt_b256(&header.state_root);
    let h_transactions_root = fmt_b256(&header.transactions_root);
    let h_receipts_root = fmt_b256(&header.receipts_root);
    let h_logs_bloom = fmt_bloom(&header.logs_bloom);
    let h_difficulty = fmt_u256(&header.difficulty);
    let h_number = header.number;
    let h_gas_limit = header.gas_limit;
    let h_gas_used = header.gas_used;
    let h_timestamp = header.timestamp;
    let h_extra_data = fmt_bytes(&header.extra_data);
    let h_mix_hash = fmt_b256(&header.mix_hash);
    let h_nonce = format!("0x{:016x}u64.into()", u64::from_be_bytes(header.nonce.0));
    let h_base_fee = fmt_opt_u64(header.base_fee_per_gas);
    let h_withdrawals_root = fmt_opt_b256(&header.withdrawals_root);
    let h_blob_gas_used = fmt_opt_u64(header.blob_gas_used);
    let h_excess_blob_gas = fmt_opt_u64(header.excess_blob_gas);
    let h_parent_beacon = fmt_opt_b256(&header.parent_beacon_block_root);
    let h_requests_hash = fmt_opt_b256(&header.requests_hash);

    out.push_str("pub fn genesis_header() -> Header {\n");
    out.push_str("    Header {\n");
    out.push_str(&format!("        parent_hash: {h_parent_hash},\n"));
    out.push_str(&format!("        ommers_hash: {h_ommers_hash},\n"));
    out.push_str(&format!("        beneficiary: {h_beneficiary},\n"));
    out.push_str(&format!("        state_root: {h_state_root},\n"));
    out.push_str(&format!("        transactions_root: {h_transactions_root},\n"));
    out.push_str(&format!("        receipts_root: {h_receipts_root},\n"));
    out.push_str(&format!("        logs_bloom: {h_logs_bloom},\n"));
    out.push_str(&format!("        difficulty: {h_difficulty},\n"));
    out.push_str(&format!("        number: {h_number}u64,\n"));
    out.push_str(&format!("        gas_limit: {h_gas_limit}u64,\n"));
    out.push_str(&format!("        gas_used: {h_gas_used}u64,\n"));
    out.push_str(&format!("        timestamp: {h_timestamp}u64,\n"));
    out.push_str(&format!("        extra_data: {h_extra_data},\n"));
    out.push_str(&format!("        mix_hash: {h_mix_hash},\n"));
    out.push_str(&format!("        nonce: {h_nonce},\n"));
    out.push_str(&format!("        base_fee_per_gas: {h_base_fee},\n"));
    out.push_str(&format!("        withdrawals_root: {h_withdrawals_root},\n"));
    out.push_str(&format!("        blob_gas_used: {h_blob_gas_used},\n"));
    out.push_str(&format!("        excess_blob_gas: {h_excess_blob_gas},\n"));
    out.push_str(&format!("        parent_beacon_block_root: {h_parent_beacon},\n"));
    out.push_str(&format!("        requests_hash: {h_requests_hash},\n"));
    out.push_str("    }\n");
    out.push_str("}\n");

    write_if_changed(&src_dir.join("fluent_genesis.rs"), out.as_bytes());
}