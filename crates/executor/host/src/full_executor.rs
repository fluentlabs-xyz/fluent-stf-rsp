use alloy_provider::Provider;
use either::Either;
use reth_primitives_traits::NodePrimitives;
use rsp_client_executor::io::ClientExecutorInput;
use serde::de::DeserializeOwned;
use std::{
    fmt::{Debug, Formatter},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::sleep;
use tracing::warn;

#[cfg(feature = "sp1")]
use {
    alloy_primitives::B256,
    eyre::bail,
    sp1_sdk::{Elf, Prover, ProvingKey, SP1Stdin, SP1VerifyingKey},
    std::time::Instant,
    tracing::info,
};

#[cfg(feature = "sp1")]
use crate::executor_components::MaybeProveWithCycles;

#[cfg(all(feature = "nitro", not(feature = "sp1")))]
use tracing::info;

use crate::{Config, ExecutionHooks, ExecutorComponents, HostExecutor};

#[cfg(feature = "sp1")]
use crate::HostError;

#[cfg(feature = "nitro")]
use {
    crate::NitroConfig,
    nitro_types::{EnclaveResponse, EthExecutionResponse},
    serde::Deserialize,
    std::fs,
    std::io::{Read, Write},
    tokio::process::Command as TokioCommand,
    vsock::VsockAddr,
    vsock::VsockStream,
};

#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[cfg(feature = "nitro")]
#[derive(Debug, serde::Serialize)]
struct EnclaveRequest {
    credentials: AwsCredentials,
    encrypted_data_key: Option<Vec<u8>>,
}

pub type EitherExecutor<C, P> = Either<FullExecutor<C, P>, CachedExecutor<C>>;

#[cfg(feature = "sp1")]
pub async fn build_executor<C, P>(
    elf: Vec<u8>,
    provider: Option<P>,
    evm_config: C::EvmConfig,
    client: Arc<C::Prover>,
    hooks: C::Hooks,
    config: Config,
) -> eyre::Result<EitherExecutor<C, P>>
where
    C: ExecutorComponents,
    C::Prover: Prover + MaybeProveWithCycles,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    if let Some(provider) = provider {
        return Ok(Either::Left(
            FullExecutor::try_new(provider, elf, evm_config, client, hooks, config).await?,
        ));
    }

    if let Some(cache_dir) = &config.cache_dir {
        return Ok(Either::Right(
            CachedExecutor::try_new(elf, client, hooks, cache_dir.clone(), config).await?,
        ));
    }

    bail!("Either a RPC URL or a cache dir must be provided")
}

#[cfg(feature = "nitro")]
pub async fn build_executor_with_nitro<C, P>(
    binary_path: PathBuf,
    provider: Option<P>,
    evm_config: C::EvmConfig,
    client: Arc<C::Prover>,
    hooks: C::Hooks,
    config: Config,
) -> eyre::Result<FullExecutor<C, P>>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    let client_dir = binary_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| eyre::eyre!("Invalid binary path"))?;
    let binary_name = binary_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| eyre::eyre!("Invalid binary name"))?;

    let temp_dir = client_dir.join("target").join("nitro-enclave-build");
    fs::create_dir_all(&temp_dir)
        .map_err(|e| eyre::eyre!("Failed to create temp directory: {}", e))?;
    info!("Created temp directory at: {:?}", temp_dir);

    let docker_binary_path = temp_dir.join(binary_name);
    fs::copy(&binary_path, &docker_binary_path)
        .map_err(|e| eyre::eyre!("Failed to copy binary to temp directory: {}", e))?;
    info!("Copied binary to: {:?}", docker_binary_path);

    let dockerfile_content = format!(
        r#"FROM alpine:latest
            COPY {} .
            CMD ["./{}"]
        "#,
        binary_name, binary_name
    );

    let dockerfile_path = temp_dir.join("Dockerfile");
    fs::write(&dockerfile_path, dockerfile_content)
        .map_err(|e| eyre::eyre!("Failed to write Dockerfile: {}", e))?;
    info!("Created Dockerfile at: {:?}", dockerfile_path);

    let eif_name = "rsp-client-enclave";
    info!("Building Docker image...");
    let docker_build_output = TokioCommand::new("docker")
        .args([
            "build",
            "-t",
            eif_name,
            "-f",
            dockerfile_path.to_str().unwrap(),
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to execute docker build: {}", e))?;

    if !docker_build_output.status.success() {
        let stderr = String::from_utf8_lossy(&docker_build_output.stderr);
        return Err(eyre::eyre!("Docker build failed: {}", stderr));
    }

    let eif_path = client_dir.join(format!("{}.eif", eif_name));
    info!("Building EIF with nitro-cli...");
    let nitro_build_output = TokioCommand::new("nitro-cli")
        .args([
            "build-enclave",
            "--docker-uri",
            eif_name,
            "--output-file",
            eif_path.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to execute nitro-cli build-enclave: {}", e))?;

    if !nitro_build_output.status.success() {
        let stderr = String::from_utf8_lossy(&nitro_build_output.stderr);
        return Err(eyre::eyre!("nitro-cli build-enclave failed: {}", stderr));
    }

    info!("EIF built successfully at: {:?}", eif_path);

    if let Err(e) = fs::remove_dir_all(&temp_dir) {
        warn!("Failed to remove temp directory: {}", e);
    }

    info!("Running enclave...");
    let run_output = TokioCommand::new("nitro-cli")
        .args([
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
        .output()
        .await
        .map_err(|e| eyre::eyre!("Failed to execute nitro-cli run-enclave: {}", e))?;

    if !run_output.status.success() {
        let stderr = String::from_utf8_lossy(&run_output.stderr);
        return Err(eyre::eyre!("nitro-cli run-enclave failed: {}", stderr));
    }

    info!("Enclave running successfully");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let nitro_config = config.nitro_config.as_ref().cloned().unwrap_or_default();

    info!("Initializing enclave key management...");
    initialize_enclave_key(nitro_config).await?;

    let provider =
        provider.ok_or_else(|| eyre::eyre!("Provider is required for Nitro executor"))?;

    Ok(FullExecutor {
        provider,
        host_executor: HostExecutor::new(
            evm_config,
            Arc::new(C::try_into_chain_spec(&config.genesis)?),
        ),
        client,
        hooks,
        config,
    })
}

pub trait BlockExecutor<C: ExecutorComponents> {
    #[allow(async_fn_in_trait)]
    async fn execute(&self, block_number: u64) -> eyre::Result<()>;

    fn client(&self) -> Arc<C::Prover>;

    #[cfg(feature = "sp1")]
    fn pk(&self) -> Arc<<C::Prover as Prover>::ProvingKey>
    where
        C::Prover: Prover;

    #[cfg(feature = "sp1")]
    fn vk(&self) -> Arc<SP1VerifyingKey>
    where
        C::Prover: Prover;

    fn config(&self) -> &Config;
}

#[cfg(feature = "sp1")]
async fn process_client<C: ExecutorComponents>(
    client: &Arc<C::Prover>,
    config: &Config,
    client_input: ClientExecutorInput<C::Primitives>,
    hooks: &C::Hooks,
    pk: &Arc<<C::Prover as Prover>::ProvingKey>,
    vk: &Arc<SP1VerifyingKey>,
) -> eyre::Result<()>
where
    C::Prover: Prover + MaybeProveWithCycles,
{
    let mut stdin = SP1Stdin::new();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    if config.skip_client_execution {
        info!("Client execution skipped");
    } else {
        let elf = pk.elf().clone();

        let (mut public_values, execution_report) =
            client.execute(elf, stdin.clone()).await.map_err(|err| eyre::eyre!("{err}"))?;

        let parent_hash = public_values.read::<B256>();
        let block_hash = public_values.read::<B256>();
        let input_block_hash = client_input.current_block.header.hash_slow();

        if input_block_hash != block_hash {
            return Err(HostError::HeaderMismatch(block_hash, input_block_hash))?;
        }

        if client_input.current_block.header.parent_hash != parent_hash {
            return Err(HostError::HeaderMismatch(block_hash, input_block_hash))?;
        }

        info!(?block_hash, "Execution successful");

        hooks
            .on_execution_end::<C::Primitives>(&client_input.current_block, &execution_report)
            .await?;
    }

    if let Some(prove_mode) = config.prove_mode {
        info!("Starting proof generation");

        let proving_start = Instant::now();
        hooks.on_proving_start(client_input.current_block.number).await?;

        let (proof, cycle_count) = client
            .prove_with_cycles(pk.as_ref(), stdin, prove_mode)
            .await
            .map_err(|err| eyre::eyre!("{err}"))?;

        let proving_duration = proving_start.elapsed();
        let proof_bytes = bincode::serialize(&proof.proof).unwrap();

        hooks
            .on_proving_end(
                client_input.current_block.number,
                &proof_bytes,
                vk.as_ref(),
                cycle_count,
                proving_duration,
            )
            .await?;

        info!("Proof successfully generated!");
    }

    Ok(())
}

#[cfg(feature = "nitro")]
async fn process_nitro_client<C: ExecutorComponents>(
    config: &Config,
    client_input: ClientExecutorInput<C::Primitives>,
    _hooks: &C::Hooks,
) -> eyre::Result<()> {
    let nitro_config = config.nitro_config.as_ref().cloned().unwrap_or_default();
    let enclave_cid = nitro_config.enclave_cid;
    let enclave_port = nitro_config.enclave_port;

    info!("Connecting to Nitro enclave at CID={} PORT={}", enclave_cid, enclave_port);

    let payload = bincode::serialize(&client_input)?;
    info!("Serialized input: {} bytes", payload.len());

    let response = tokio::task::spawn_blocking(move || -> eyre::Result<EthExecutionResponse> {
        const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
        let addr = VsockAddr::new(enclave_cid, enclave_port);
        let mut stream = VsockStream::connect(&addr).map_err(|e| {
            eyre::eyre!("Failed to connect to VSOCK {}:{}: {}", enclave_cid, enclave_port, e)
        })?;

        let req_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| eyre::eyre!("Payload too large: {} bytes", payload.len()))?;
        stream
            .write_all(&req_len.to_be_bytes())
            .map_err(|e| eyre::eyre!("Failed to write request length to enclave: {}", e))?;
        stream
            .write_all(&payload)
            .map_err(|e| eyre::eyre!("Failed to write payload to enclave: {}", e))?;
        stream.flush().map_err(|e| eyre::eyre!("Failed to flush stream: {}", e))?;

        info!("Sent {} bytes to enclave", payload.len());

        let mut resp_len_buf = [0u8; 4];
        stream
            .read_exact(&mut resp_len_buf)
            .map_err(|e| eyre::eyre!("Failed to read response length from enclave: {}", e))?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len > MAX_FRAME_SIZE {
            return Err(eyre::eyre!(
                "Response frame too large: {} bytes (cap {})",
                resp_len,
                MAX_FRAME_SIZE
            ));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .map_err(|e| eyre::eyre!("Failed to read response body from enclave: {}", e))?;

        let resp_text = String::from_utf8_lossy(&resp_buf);
        info!("Received response ({} bytes): {}", resp_buf.len(), resp_text);

        let parsed: EthExecutionResponse = bincode::deserialize(&resp_buf)
            .map_err(|e| eyre::eyre!("Failed to parse response from enclave: {}", e))?;

        Ok(parsed)
    })
    .await
    .map_err(|e| eyre::eyre!("Task join error: {}", e))??;

    // TODO: verify response.leaf against client_input block hashes
    info!(block_number = response.block_number, "Nitro enclave execution successful");
    Ok(())
}
#[cfg(feature = "nitro")]
fn aws_access_key_id() -> String {
    std::env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID environment variable must be set")
}

#[cfg(feature = "nitro")]
fn aws_secret_access_key() -> String {
    std::env::var("AWS_SECRET_ACCESS_KEY")
        .expect("AWS_SECRET_ACCESS_KEY environment variable must be set")
}

#[cfg(feature = "nitro")]
fn aws_session_token() -> Option<String> {
    std::env::var("AWS_SESSION_TOKEN").ok().filter(|s| !s.is_empty())
}

#[cfg(feature = "nitro")]
fn data_key_storage() -> String {
    std::env::var("DATA_KEY_STORAGE").unwrap_or_else(|_| "./data_key.enc".to_string())
}

#[cfg(feature = "nitro")]
fn attestation_storage() -> String {
    std::env::var("ATTESTATION_KEY_STORAGE").unwrap_or_else(|_| "./attestation.bin".to_string())
}

#[cfg(feature = "nitro")]
async fn initialize_enclave_key(nitro_config: NitroConfig) -> eyre::Result<()> {
    let data_key_path = data_key_storage();
    let encrypted_dek = match fs::read(&data_key_path) {
        Ok(data) => {
            info!("Found existing encrypted data key, requesting decryption");
            Some(data)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("No existing key found, requesting new key creation");
            None
        }
        Err(err) => return Err(eyre::eyre!("Failed to read data key file: {}", err)),
    };

    let request = EnclaveRequest {
        credentials: AwsCredentials {
            access_key_id: aws_access_key_id(),
            secret_access_key: aws_secret_access_key(),
            session_token: aws_session_token(),
        },
        encrypted_data_key: encrypted_dek.clone(),
    };

    let resp =
        handle_key_management_request(nitro_config.enclave_cid, nitro_config.enclave_port, request)
            .await?;

    match resp {
        Some(EnclaveResponse::KeyGenerated { public_key, attestation }) => {
            let attestation_path = attestation_storage();
            if let Some(parent) = Path::new(&attestation_path).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&attestation_path, &attestation)?;
            info!("Attestation saved");
            info!("public_key: {:?}", hex::encode(&public_key));
            Ok(())
        }
        Some(EnclaveResponse::AlreadyInitialized { public_key, .. }) => {
            info!("Enclave already initialized, public_key: {:?}", hex::encode(&public_key));
            Ok(())
        }
        Some(EnclaveResponse::Error(e)) => Err(eyre::eyre!("Key management failed: {}", e)),
        _ => Ok(()),
    }
}

#[cfg(feature = "nitro")]
async fn handle_key_management_request(
    enclave_cid: u32,
    enclave_port: u32,
    req: EnclaveRequest,
) -> eyre::Result<Option<EnclaveResponse>> {
    use std::io::{Read, Write};

    info!("Handling key management request: {:?}", req);

    const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
    let addr = VsockAddr::new(enclave_cid, enclave_port);
    let mut stream = VsockStream::connect(&addr)
        .map_err(|e| eyre::eyre!("Failed to connect to enclave for key management: {}", e))?;

    let req_bytes = bincode::serialize(&req)
        .map_err(|e| eyre::eyre!("Failed to serialize key request: {}", e))?;
    let req_len = req_bytes.len() as u32;
    stream
        .write_all(&req_len.to_be_bytes())
        .map_err(|e| eyre::eyre!("Failed to write request length: {}", e))?;
    stream.write_all(&req_bytes).map_err(|e| eyre::eyre!("Failed to write request: {}", e))?;
    stream.flush().map_err(|e| eyre::eyre!("Failed to flush: {}", e))?;

    if req.encrypted_data_key.is_none() {
        let mut resp_len_buf = [0u8; 4];
        stream
            .read_exact(&mut resp_len_buf)
            .map_err(|e| eyre::eyre!("Failed to read response length: {}", e))?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len > MAX_FRAME_SIZE {
            return Err(eyre::eyre!(
                "Response frame too large: {} bytes (cap {})",
                resp_len,
                MAX_FRAME_SIZE
            ));
        }
        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .map_err(|e| eyre::eyre!("Failed to read response: {}", e))?;

        let response: EnclaveResponse = bincode::deserialize(&resp_buf)
            .map_err(|e| eyre::eyre!("Failed to deserialize response: {}", e))?;

        Ok(Some(response))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "nitro")]
fn deserialize_b256_from_hex<'de, D>(deserializer: D) -> Result<alloy_primitives::B256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(s)
        .map_err(|e| serde::de::Error::custom(format!("Failed to decode hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(format!("Expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(alloy_primitives::B256::from(arr))
}

#[cfg(feature = "sp1")]
impl<C, P> BlockExecutor<C> for EitherExecutor<C, P>
where
    C: ExecutorComponents,
    C::Prover: Prover + MaybeProveWithCycles,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        match self {
            Either::Left(ref executor) => executor.execute(block_number).await,
            Either::Right(ref executor) => executor.execute(block_number).await,
        }
    }

    fn client(&self) -> Arc<C::Prover> {
        match self {
            Either::Left(ref executor) => executor.client.clone(),
            Either::Right(ref executor) => executor.client.clone(),
        }
    }

    fn pk(&self) -> Arc<<C::Prover as Prover>::ProvingKey>
    where
        C::Prover: Prover,
    {
        match self {
            Either::Left(ref executor) => executor.pk.clone(),
            Either::Right(ref executor) => executor.pk.clone(),
        }
    }

    fn vk(&self) -> Arc<SP1VerifyingKey>
    where
        C::Prover: Prover,
    {
        match self {
            Either::Left(ref executor) => executor.vk.clone(),
            Either::Right(ref executor) => executor.vk.clone(),
        }
    }

    fn config(&self) -> &Config {
        match self {
            Either::Left(executor) => &executor.config,
            Either::Right(executor) => &executor.config,
        }
    }
}

#[cfg(feature = "sp1")]
pub struct FullExecutor<C: ExecutorComponents, P>
where
    C::Prover: Prover,
{
    provider: P,
    host_executor: HostExecutor<C::EvmConfig, C::ChainSpec>,
    client: Arc<C::Prover>,
    pk: Arc<<C::Prover as Prover>::ProvingKey>,
    vk: Arc<SP1VerifyingKey>,
    hooks: C::Hooks,
    config: Config,
}

#[cfg(not(feature = "sp1"))]
pub struct FullExecutor<C: ExecutorComponents, P> {
    provider: P,
    host_executor: HostExecutor<C::EvmConfig, C::ChainSpec>,
    client: Arc<C::Prover>,
    hooks: C::Hooks,
    config: Config,
}

#[cfg(feature = "sp1")]
impl<C, P> FullExecutor<C, P>
where
    C: ExecutorComponents,
    C::Prover: Prover,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    pub async fn try_new(
        provider: P,
        elf: Vec<u8>,
        evm_config: C::EvmConfig,
        client: Arc<C::Prover>,
        hooks: C::Hooks,
        config: Config,
    ) -> eyre::Result<Self> {
        // Setup the proving key.
        let pk =
            client.setup(Elf::from(elf.as_slice())).await.map_err(|err| eyre::eyre!("{err}"))?;
        let vk = pk.verifying_key().clone();

        Ok(Self {
            provider,
            host_executor: HostExecutor::new(
                evm_config,
                Arc::new(C::try_into_chain_spec(&config.genesis)?),
            ),
            client,
            pk: Arc::new(pk),
            vk: Arc::new(vk),
            hooks,
            config,
        })
    }

    pub async fn wait_for_block(&self, block_number: u64) -> eyre::Result<()> {
        let block_number = block_number.into();

        while self.provider.get_block_by_number(block_number).await?.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    async fn load_client_input(
        &self,
        block_number: u64,
    ) -> eyre::Result<ClientExecutorInput<C::Primitives>> {
        load_client_input_inner::<C, P>(
            &self.config,
            &self.host_executor,
            &self.provider,
            block_number,
        )
        .await
    }
}

#[cfg(not(feature = "sp1"))]
impl<C, P> FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    pub async fn wait_for_block(&self, block_number: u64) -> eyre::Result<()> {
        let block_number = block_number.into();

        while self.provider.get_block_by_number(block_number).await?.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    async fn load_client_input(
        &self,
        block_number: u64,
    ) -> eyre::Result<ClientExecutorInput<C::Primitives>> {
        load_client_input_inner::<C, P>(
            &self.config,
            &self.host_executor,
            &self.provider,
            block_number,
        )
        .await
    }
}

async fn load_client_input_inner<C, P>(
    config: &Config,
    host_executor: &HostExecutor<C::EvmConfig, C::ChainSpec>,
    provider: &P,
    block_number: u64,
) -> eyre::Result<ClientExecutorInput<C::Primitives>>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    let client_input_from_cache = config.cache_dir.as_ref().and_then(|cache_dir| {
        match try_load_input_from_cache::<C::Primitives>(cache_dir, config.chain.id(), block_number)
        {
            Ok(client_input) => client_input,
            Err(e) => {
                warn!("Failed to load input from cache: {}", e);
                None
            }
        }
    });

    match client_input_from_cache {
        Some(mut client_input_from_cache) => {
            client_input_from_cache.opcode_tracking = config.opcode_tracking;
            Ok(client_input_from_cache)
        }
        None => {
            let client_input = host_executor
                .execute(
                    block_number,
                    provider,
                    config.genesis.clone(),
                    config.custom_beneficiary,
                    config.opcode_tracking,
                )
                .await?;

            if let Some(ref cache_dir) = config.cache_dir {
                let input_folder = cache_dir.join(format!("input/{}", config.chain.id()));
                if !input_folder.exists() {
                    std::fs::create_dir_all(&input_folder)?;
                }

                let input_path = input_folder.join(format!("{block_number}.bin"));
                let mut cache_file = std::fs::File::create(input_path)?;

                bincode::serialize_into(&mut cache_file, &client_input)?;
            }

            Ok(client_input)
        }
    }
}

#[cfg(feature = "sp1")]
impl<C, P> BlockExecutor<C> for FullExecutor<C, P>
where
    C: ExecutorComponents,
    C::Prover: Prover + MaybeProveWithCycles,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        self.hooks.on_execution_start(block_number).await?;
        let client_input = self.load_client_input(block_number).await?;
        process_client::<C>(
            &self.client,
            &self.config,
            client_input,
            &self.hooks,
            &self.pk,
            &self.vk,
        )
        .await
    }

    fn client(&self) -> Arc<C::Prover> {
        self.client.clone()
    }
    fn pk(&self) -> Arc<<C::Prover as Prover>::ProvingKey>
    where
        C::Prover: Prover,
    {
        self.pk.clone()
    }
    fn vk(&self) -> Arc<SP1VerifyingKey>
    where
        C::Prover: Prover,
    {
        self.vk.clone()
    }
    fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(all(feature = "nitro", not(feature = "sp1")))]
impl<C, P> BlockExecutor<C> for FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        self.hooks.on_execution_start(block_number).await?;
        let client_input = self.load_client_input(block_number).await?;
        process_nitro_client::<C>(&self.config, client_input, &self.hooks).await
    }

    fn client(&self) -> Arc<C::Prover> {
        self.client.clone()
    }
    fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(feature = "sp1")]
impl<C, P> Debug for FullExecutor<C, P>
where
    C: ExecutorComponents,
    C::Prover: Prover,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullExecutor").field("config", &self.config).finish()
    }
}

#[cfg(not(feature = "sp1"))]
impl<C, P> Debug for FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullExecutor").field("config", &self.config).finish()
    }
}

#[cfg(feature = "sp1")]
pub struct CachedExecutor<C>
where
    C: ExecutorComponents,
    C::Prover: Prover,
{
    cache_dir: PathBuf,
    client: Arc<C::Prover>,
    pk: Arc<<C::Prover as Prover>::ProvingKey>,
    vk: Arc<SP1VerifyingKey>,
    hooks: C::Hooks,
    config: Config,
}

#[cfg(not(feature = "sp1"))]
pub struct CachedExecutor<C>
where
    C: ExecutorComponents,
{
    cache_dir: PathBuf,
    client: Arc<C::Prover>,
    hooks: C::Hooks,
    config: Config,
}

#[cfg(feature = "sp1")]
impl<C> CachedExecutor<C>
where
    C: ExecutorComponents,
    C::Prover: Prover,
{
    pub async fn try_new(
        elf: Vec<u8>,
        client: Arc<C::Prover>,
        hooks: C::Hooks,
        cache_dir: PathBuf,
        config: Config,
    ) -> eyre::Result<Self> {
        // Setup the proving key.
        let pk =
            client.setup(Elf::from(elf.as_slice())).await.map_err(|err| eyre::eyre!("{err}"))?;
        let vk = pk.verifying_key().clone();

        Ok(Self { cache_dir, client, pk: Arc::new(pk), vk: Arc::new(vk), hooks, config })
    }
}

#[cfg(feature = "sp1")]
impl<C> BlockExecutor<C> for CachedExecutor<C>
where
    C: ExecutorComponents,
    C::Prover: Prover + MaybeProveWithCycles,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        let client_input = try_load_input_from_cache::<C::Primitives>(
            &self.cache_dir,
            self.config.chain.id(),
            block_number,
        )?
        .ok_or(eyre::eyre!("No cached input found"))?;

        process_client::<C>(
            &self.client,
            &self.config,
            client_input,
            &self.hooks,
            &self.pk,
            &self.vk,
        )
        .await
    }

    fn client(&self) -> Arc<C::Prover> {
        self.client.clone()
    }
    fn pk(&self) -> Arc<<C::Prover as Prover>::ProvingKey>
    where
        C::Prover: Prover,
    {
        self.pk.clone()
    }
    fn vk(&self) -> Arc<SP1VerifyingKey>
    where
        C::Prover: Prover,
    {
        self.vk.clone()
    }
    fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(feature = "sp1")]
impl<C> Debug for CachedExecutor<C>
where
    C: ExecutorComponents,
    C::Prover: Prover,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedExecutor").field("cache_dir", &self.cache_dir).finish()
    }
}

#[cfg(not(feature = "sp1"))]
impl<C> Debug for CachedExecutor<C>
where
    C: ExecutorComponents,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedExecutor").field("cache_dir", &self.cache_dir).finish()
    }
}

fn try_load_input_from_cache<P: NodePrimitives + DeserializeOwned>(
    cache_dir: &Path,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<ClientExecutorInput<P>>> {
    let cache_path = cache_dir.join(format!("input/{chain_id}/{block_number}.bin"));

    if cache_path.exists() {
        // TODO: prune the cache if invalid instead
        let mut cache_file = std::fs::File::open(cache_path)?;
        let client_input = bincode::deserialize_from(&mut cache_file)?;

        Ok(Some(client_input))
    } else {
        Ok(None)
    }
}
