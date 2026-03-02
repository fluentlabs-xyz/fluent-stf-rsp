use std::{fs, path::{Path, PathBuf}};
use alloy_primitives::U256;
use serde_json::Value;

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

fn emit_account(addr: &str, account: &Value, bin_dir: &Path) -> String {
    let addr_clean = format!("{:0>40}", addr.trim_start_matches("0x").to_lowercase());

    let balance_hex = account["balance"].as_str().unwrap_or("0x0");
    let balance_u256 = U256::from_str_radix(balance_hex.trim_start_matches("0x"), 16).unwrap();
    let balance_bytes = balance_u256.to_be_bytes::<32>();
    let balance_lit = format!(
        "U256::from_be_bytes([{}])",
        balance_bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    );

    let nonce_lit = match account["nonce"].as_str() {
        Some(n) => format!(
            "Some({}u64)",
            u64::from_str_radix(n.trim_start_matches("0x"), 16).unwrap()
        ),
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
                format!(r#"Some(Bytes::from_static(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fluent_genesis_bin/{fname}"))))"#)
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

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    let genesis_path = manifest_dir
        .join("../../bin/host/genesis/genesis-v0.5.3.json");

    let src_dir = manifest_dir.join("src");
    let bin_dir = src_dir.join("fluent_genesis_bin");
    fs::create_dir_all(&bin_dir).unwrap();

    let raw = fs::read_to_string(&genesis_path).expect("genesis.json not found");
    let json: Value = serde_json::from_str(&raw).expect("failed to parse genesis.json");
    let alloc = json["alloc"].as_object().expect("no alloc field");
    let count = alloc.len();

    let mut out = String::new();

    // ── header ───────────────────────────────────────────────────────────────

    out.push_str("// @generated — do not edit manually\n");
    out.push_str("#![allow(clippy::all)]\n");
    out.push_str("use alloy_primitives::{address, b256, U256, Bytes, Address};\n");
    out.push_str("use alloy_genesis::{Genesis, GenesisAccount, ChainConfig};\n");
    out.push_str("use std::collections::BTreeMap;\n");
    out.push('\n');

    // ── alloc ─────────────────────────────────────────────────────────────────

    out.push_str(&format!("pub const ALLOC_LEN: usize = {count};\n\n"));
    out.push_str("pub fn genesis_alloc() -> [(Address, GenesisAccount); ALLOC_LEN] {\n");
    out.push_str("    [\n");

    for (addr, account) in alloc {
        let entry = emit_account(addr, account, &bin_dir);
        out.push_str(&format!("        {entry},\n"));
    }

    out.push_str("    ]\n");
    out.push_str("}\n\n");

    // ── config ────────────────────────────────────────────────────────────────

    let cfg = &json["config"];

    let chain_id       = cfg["chainId"].as_u64().unwrap_or(1337);
    let homestead      = cfg["homesteadBlock"].as_u64().unwrap_or(0);
    let dao_fork_blk   = cfg["daoForkBlock"].as_u64().unwrap_or(0);
    let dao_fork_sup   = cfg["daoForkSupport"].as_bool().unwrap_or(false);
    let eip150         = cfg["eip150Block"].as_u64().unwrap_or(0);
    let eip155         = cfg["eip155Block"].as_u64().unwrap_or(0);
    let eip158         = cfg["eip158Block"].as_u64().unwrap_or(0);
    let byzantium      = cfg["byzantiumBlock"].as_u64().unwrap_or(0);
    let constantinople = cfg["constantinopleBlock"].as_u64().unwrap_or(0);
    let petersburg     = cfg["petersburgBlock"].as_u64().unwrap_or(0);
    let istanbul       = cfg["istanbulBlock"].as_u64().unwrap_or(0);
    let muir_glacier   = cfg["muirGlacierBlock"].as_u64().unwrap_or(0);
    let berlin         = cfg["berlinBlock"].as_u64().unwrap_or(0);
    let london         = cfg["londonBlock"].as_u64().unwrap_or(0);
    let arrow_glacier  = cfg["arrowGlacierBlock"].as_u64().unwrap_or(0);
    let gray_glacier   = cfg["grayGlacierBlock"].as_u64().unwrap_or(0);
    let merge_netsplit = cfg["mergeNetsplitBlock"].as_u64().unwrap_or(0);
    let shanghai_time  = cfg["shanghaiTime"].as_u64().unwrap_or(0);
    let cancun_time    = cfg["cancunTime"].as_u64().unwrap_or(0);
    let prague_time    = cfg["pragueTime"].as_u64().unwrap_or(0);
    let osaka_time     = cfg["osakaTime"].as_u64().unwrap_or(999999999999);
    let ttd_passed     = cfg["terminalTotalDifficultyPassed"].as_bool().unwrap_or(false);

    // ── top-level fields ──────────────────────────────────────────────────────

    let timestamp = u64::from_str_radix(
        json["timestamp"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
    ).unwrap();
    let gas_limit = u64::from_str_radix(
        json["gasLimit"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
    ).unwrap();
    let nonce = u64::from_str_radix(
        json["nonce"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
    ).unwrap();
    let number = u64::from_str_radix(
        json["number"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
    ).unwrap();

    let difficulty_bytes = U256::from_str_radix(
        json["difficulty"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16
    ).unwrap().to_be_bytes::<32>();
    let difficulty_lit = format!(
        "U256::from_be_bytes([{}])",
        difficulty_bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    );

    let mix_hash = format!(
        "{:0>64}",
        json["mixHash"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );
    let coinbase = format!(
        "{:0>40}",
        json["coinbase"].as_str().unwrap_or("0x0").trim_start_matches("0x")
    );

    let extra_data_bytes = hex::decode(
        json["extraData"].as_str().unwrap_or("0x").trim_start_matches("0x")
    ).unwrap();
    let extra_data_lit = format!(
        "Bytes::from_static(&[{}])",
        extra_data_bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
    );

    // ── genesis() ─────────────────────────────────────────────────────────────

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
    out.push_str("}\n");

    write_if_changed(&src_dir.join("fluent_genesis.rs"), out.as_bytes());

    println!("cargo:rerun-if-changed={}", genesis_path.display());
}