use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(feature = "sp1")]
use sp1_build::build_program;

fn main() {
    #[cfg(feature = "sp1")]
    {
        println!("cargo:warning=Building SP1 program");
        build_program("../client");
    }

    #[cfg(feature = "nitro")]
    {
        println!("cargo:warning=Building Nitro binary");
        if let Err(e) = build_nitro_binary() {
            panic!("Failed to build Nitro binary: {}", e);
        }
    }
}

#[cfg(feature = "nitro")]
fn build_nitro_binary() -> Result<(), Box<dyn std::error::Error>> {
    let client_dir = PathBuf::from("../client");
    let target = "x86_64-unknown-linux-musl";
    let binary_name = "rsp-client";

    println!("cargo:warning=Checking for musl target...");
    let target_list = Command::new("rustup").args(&["target", "list", "--installed"]).output()?;

    let target_list_str = String::from_utf8_lossy(&target_list.stdout);
    if !target_list_str.contains(target) {
        println!("cargo:warning=Installing musl target...");
        let install_status = Command::new("rustup").args(&["target", "add", target]).status()?;

        if !install_status.success() {
            return Err(format!("Failed to install target: {}", target).into());
        }
    }

    println!("cargo:warning=Building for target: {}", target);
    let build_output = Command::new("cargo")
        .args(&[
            "build",
            "--target",
            target,
            "--release",
            "--manifest-path",
            client_dir.join("Cargo.toml").to_str().unwrap(),
            "--features",
            "nitro",
            "--no-default-features",
        ])
        .output()?;

    if !build_output.status.success() {
        let stderr = String::from_utf8_lossy(&build_output.stderr);
        return Err(format!("Cargo build failed: {}", stderr).into());
    }

    let binary_path = client_dir.join("target").join(target).join("release").join(binary_name);

    if !binary_path.exists() {
        return Err(format!("Binary not found at: {:?}", binary_path).into());
    }

    println!("cargo:warning=Binary built successfully at: {:?}", binary_path);
    Ok(())
}
