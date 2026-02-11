// #[cfg(feature = "sp1")]
use sp1_build::build_program;
#[cfg(feature = "nitro")]
use {
    cargo_metadata::Metadata,
    std::path::{Path, PathBuf},
    std::process::Command,
};

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

        println!("cargo:warning=Building SP1 aws-nitro-validator");
        build_program("../aws-nitro-validator");
    }
}

#[cfg(feature = "nitro")]
fn build_nitro_binary() -> Result<(), Box<dyn std::error::Error>> {
    let client_dir = PathBuf::from("../client");
    let target = "x86_64-unknown-linux-musl";
    let binary_name = "rsp-client";

    let metadata_file = client_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    cargo_rerun_if_changed(&metadata, &client_dir);

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

#[cfg(feature = "nitro")]
pub(crate) fn cargo_rerun_if_changed(metadata: &Metadata, program_dir: &Path) {
    // Tell cargo to rerun the script only if program/{src, bin, build.rs, Cargo.toml} changes
    // Ref: https://doc.rust-lang.org/nightly/cargo/reference/build-scripts.html#rerun-if-changed
    let dirs = vec![
        program_dir.join("src"),
        program_dir.join("bin"),
        program_dir.join("build.rs"),
        program_dir.join("Cargo.toml"),
    ];
    for dir in dirs {
        if dir.exists() {
            println!("cargo::rerun-if-changed={}", dir.canonicalize().unwrap().display());
        }
    }

    // Re-run the build script if the workspace root's Cargo.lock changes. If the program is its own
    // workspace, this will be the program's Cargo.lock.
    println!("cargo:rerun-if-changed={}", metadata.workspace_root.join("Cargo.lock").as_str());

    // Re-run if any local dependency changes.
    for package in &metadata.packages {
        for dependency in &package.dependencies {
            if let Some(path) = &dependency.path {
                println!("cargo:rerun-if-changed={}", path.as_str());
            }
        }
    }
}
