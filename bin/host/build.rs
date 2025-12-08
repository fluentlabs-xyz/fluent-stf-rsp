use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(feature = "sp1")]
use sp1_build::build_program;

fn main() {
    let build_sp1 = env::var("CARGO_FEATURE_SP1").is_ok();
    let build_nitro = env::var("CARGO_FEATURE_NITRO").is_ok();
    println!("Nitro: {}", build_nitro);
    if build_sp1 {
        println!("cargo:warning=Building SP1 program");
        build_program("../client");
        // build_program("../client-op");
    }

    if build_nitro {
        println!("cargo:warning=Building Nitro enclave");
        if let Err(e) = build_nitro_enclave() {
            panic!("Failed to build Nitro enclave: {}", e);
        }
    }

    if !build_sp1 && !build_nitro {
        println!("cargo:warning=No feature specified, defaulting to SP1");
        #[cfg(feature = "sp1")]
        build_program("../client");
    }
}

fn build_nitro_enclave() -> Result<(), Box<dyn std::error::Error>> {
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

    let temp_dir = client_dir.join("target").join("nitro-enclave-build");
    fs::create_dir_all(&temp_dir)?;
    println!("cargo:warning=Created temp directory at: {:?}", temp_dir);

    let docker_binary_path = temp_dir.join(binary_name);
    fs::copy(&binary_path, &docker_binary_path)?;
    println!("cargo:warning=Copied binary to: {:?}", docker_binary_path);

    let dockerfile_content = format!(
        r#"FROM alpine:latest
            COPY {} .
            CMD ["./{}"]
        "#,
        binary_name, binary_name
    );

    let dockerfile_path = temp_dir.join("Dockerfile");
    fs::write(&dockerfile_path, dockerfile_content)?;
    println!("cargo:warning=Created Dockerfile at: {:?}", dockerfile_path);

    let eif_name = "rsp-client-enclave";
    println!("cargo:warning=Building Docker image...");
    let docker_build_status = Command::new("docker")
        .args(&[
            "build",
            "-t",
            eif_name,
            "-f",
            dockerfile_path.to_str().unwrap(),
            temp_dir.to_str().unwrap(),
        ])
        .status()?;

    if !docker_build_status.success() {
        return Err("Docker build failed".into());
    }

    let eif_path = client_dir.join(format!("{}.eif", eif_name));

    println!("cargo:warning=Building EIF with nitro-cli...");
    let nitro_build_status = Command::new("nitro-cli")
        .args(&[
            "build-enclave",
            "--docker-uri",
            eif_name,
            "--output-file",
            eif_path.to_str().unwrap(),
        ])
        .status()?;

    if !nitro_build_status.success() {
        return Err("nitro-cli build-enclave failed".into());
    }

    println!("cargo:warning=EIF built successfully at: {:?}", eif_path);

    println!("cargo:warning=Cleaning up temporary directory...");
    if let Err(e) = fs::remove_dir_all(&temp_dir) {
        println!("cargo:warning=Warning: Failed to remove temp directory: {}", e);
    }

    println!("cargo:warning=Running enclave...");
    let run_status = Command::new("nitro-cli")
        .args(&[
            "run-enclave",
            "--eif-path",
            eif_path.to_str().unwrap(),
            "--cpu-count",
            "2",
            "--memory",
            "256",
            "--enclave-cid",
            "10",
            "--debug-mode",
        ])
        .status()?;

    if !run_status.success() {
        return Err("nitro-cli run-enclave failed".into());
    }

    println!("cargo:warning=Enclave running successfully");
    Ok(())
}
