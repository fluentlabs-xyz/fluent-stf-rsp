//! Fake L1: Anvil + MockRollup contract.
//!
//! Provides helpers to deploy the `MockRollup` contract on a local Anvil
//! instance and interact with it (submit blob hashes, accept batches,
//! preconfirm batches).
//!
//! The contract implements the L1 interface that `blob.rs` in the proxy
//! expects: `batchBlobHashes(uint256)` view and `BatchBlobsSubmitted` event.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_sol_types::{sol, SolCall};
use eyre::{eyre, Result};
use tracing::info;

// ---------------------------------------------------------------------------
// Contract ABI + bytecode (compiled from contracts/MockRollup.sol)
// ---------------------------------------------------------------------------

sol! {
    struct L2BlockHeader {
        bytes32 previousBlockHash;
        bytes32 blockHash;
        bytes32 withdrawalRoot;
        bytes32 depositRoot;
        uint256 depositCount;
    }

    contract MockRollup {
        // Storage reads
        uint256 public nextBatchIndex;
        uint256 public lastPreconfirmedBatch;
        bytes public lastSignature;

        // Events (must match blob.rs filters)
        event BatchBlobsSubmitted(
            uint256 indexed batchIndex,
            uint256 numBlobs,
            uint256 totalSoFar
        );
        event BatchHeadersSubmitted(
            uint256 indexed batchIndex,
            bytes32 batchRoot,
            uint256 expectedBlobsCount
        );
        event BatchAccepted(uint256 indexed batchIndex);

        // Functions
        function submitBlobs(uint256 batchIndex, bytes32[] calldata blobHashes) external;
        function batchBlobHashes(uint256 batchIndex) external view returns (bytes32[] memory);
        function acceptNextBatch(L2BlockHeader[] calldata blockHeaders, uint256 expectedBlobsCount) external;
        function preconfirmBatch(address nitroVerifier, uint256 batchIndex, bytes calldata signature) external;
    }
}

/// Compiled bytecode of `contracts/MockRollup.sol` (solc 0.8.30).
/// Changes from previous version:
/// - `acceptNextBatch` takes `L2BlockHeader[]` instead of `bytes32[]`
/// - `_merkleRoot` computes real Merkle root from L2BlockHeaders
/// - `lastPreconfirmedBatch` initialized to `type(uint256).max` (sentinel for unused state)
/// - `BatchAccepted` emitted from `submitBlobs` (matches real Rollup contract; courier uses
///   this event as the "blobs ready" signal before calling /sign-batch-root)
/// - `preconfirmBatch` no longer emits `BatchAccepted`
pub const MOCK_ROLLUP_BYTECODE: &str = "0x60806040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6002553480156032575f5ffd5b5061119d806100405f395ff3fe608060405234801561000f575f5ffd5b506004361061007b575f3560e01c8063b064500011610059578063b0645000146100d7578063c6678826146100f3578063cf96dcba14610111578063d0d26f0e1461012d5761007b565b8063048e289c1461007f5780637e4fa7001461009d578063af88edf2146100bb575b5f5ffd5b61008761015d565b6040516100949190610726565b60405180910390f35b6100a5610163565b6040516100b29190610726565b60405180910390f35b6100d560048036038101906100d0919061082c565b610169565b005b6100f160048036038101906100ec91906108f2565b610188565b005b6100fb6101ef565b60405161010891906109bf565b60405180910390f35b61012b60048036038101906101269190610a34565b61027b565b005b61014760048036038101906101429190610a91565b610368565b6040516101549190610b7c565b60405180910390f35b60025481565b60015481565b82600281905550818160039182610181929190610dd0565b5050505050565b5f60015f81548092919061019b90610eca565b9190505590505f6101ac85856103ce565b9050817f96f800d0623a7e6080d7cc3bb8e6e0fb3d5841932c409b13f3304fb0e89d46ae82856040516101e0929190610f20565b60405180910390a25050505050565b600380546101fc90610c00565b80601f016020809104026020016040519081016040528092919081815260200182805461022890610c00565b80156102735780601f1061024a57610100808354040283529160200191610273565b820191905f5260205f20905b81548152906001019060200180831161025657829003601f168201915b505050505081565b5f5f90505b828290508110156102e5575f5f8581526020019081526020015f208383838181106102ae576102ad610f47565b5b90506020020135908060018154018082558091505060019003905f5260205f20015f90919091909150558080600101915050610280565b50827ff44cf3c80142f89d4e6fab4a80df6526af611649f05cae080bd0484d2b383bb1838390505f5f8781526020019081526020015f208054905060405161032e929190610f74565b60405180910390a2827fbff8365f0d7a7e4949c3319574ce4ae3a04445145d23009ea7d402c88ca6926760405160405180910390a2505050565b60605f5f8381526020019081526020015f208054806020026020016040519081016040528092919081815260200182805480156103c257602002820191905f5260205f20905b8154815260200190600101908083116103ae575b50505050509050919050565b5f5f8383905090505f81036103e8575f5f1b915050610708565b5f8167ffffffffffffffff81111561040357610402610ba6565b5b6040519080825280602002602001820160405280156104315781602001602082028036833780820191505090505b5090505f5f90505b828110156105095785858281811061045457610453610f47565b5b905060a002015f01358686838181106104705761046f610f47565b5b905060a002016020013587878481811061048d5761048c610f47565b5b905060a00201604001358888858181106104aa576104a9610f47565b5b905060a00201606001356040516020016104c79493929190610fbb565b604051602081830303815290604052805190602001208282815181106104f0576104ef610f47565b5b6020026020010181815250508080600101915050610439565b505b6001815111156106e8575f815190505f600260018361052a9190611008565b6105349190611068565b90505f8167ffffffffffffffff81111561055157610550610ba6565b5b60405190808252806020026020018201604052801561057f5781602001602082028036833780820191505090505b5090505f5f90505b6002846105949190611068565b81101561064857846002826105a99190611098565b815181106105ba576105b9610f47565b5b60200260200101518560016002846105d29190611098565b6105dc9190611008565b815181106105ed576105ec610f47565b5b60200260200101516040516020016106069291906110d9565b6040516020818303038152906040528051906020012082828151811061062f5761062e610f47565b5b6020026020010181815250508080600101915050610587565b5060016002846106589190611104565b036106dd575f8460018561066c9190611134565b8151811061067d5761067c610f47565b5b60200260200101519050808160405160200161069a9291906110d9565b60405160208183030381529060405280519060200120826001856106be9190611134565b815181106106cf576106ce610f47565b5b602002602001018181525050505b80935050505061050b565b805f815181106106fb576106fa610f47565b5b6020026020010151925050505b92915050565b5f819050919050565b6107208161070e565b82525050565b5f6020820190506107395f830184610717565b92915050565b5f5ffd5b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61077082610747565b9050919050565b61078081610766565b811461078a575f5ffd5b50565b5f8135905061079b81610777565b92915050565b6107aa8161070e565b81146107b4575f5ffd5b50565b5f813590506107c5816107a1565b92915050565b5f5ffd5b5f5ffd5b5f5ffd5b5f5f83601f8401126107ec576107eb6107cb565b5b8235905067ffffffffffffffff811115610809576108086107cf565b5b602083019150836001820283011115610825576108246107d3565b5b9250929050565b5f5f5f5f606085870312156108445761084361073f565b5b5f6108518782880161078d565b9450506020610862878288016107b7565b935050604085013567ffffffffffffffff81111561088357610882610743565b5b61088f878288016107d7565b925092505092959194509250565b5f5f83601f8401126108b2576108b16107cb565b5b8235905067ffffffffffffffff8111156108cf576108ce6107cf565b5b6020830191508360a08202830111156108eb576108ea6107d3565b5b9250929050565b5f5f5f604084860312156109095761090861073f565b5b5f84013567ffffffffffffffff81111561092657610925610743565b5b6109328682870161089d565b93509350506020610945868287016107b7565b9150509250925092565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f6109918261094f565b61099b8185610959565b93506109ab818560208601610969565b6109b481610977565b840191505092915050565b5f6020820190508181035f8301526109d78184610987565b905092915050565b5f5f83601f8401126109f4576109f36107cb565b5b8235905067ffffffffffffffff811115610a1157610a106107cf565b5b602083019150836020820283011115610a2d57610a2c6107d3565b5b9250929050565b5f5f5f60408486031215610a4b57610a4a61073f565b5b5f610a58868287016107b7565b935050602084013567ffffffffffffffff811115610a7957610a78610743565b5b610a85868287016109df565b92509250509250925092565b5f60208284031215610aa657610aa561073f565b5b5f610ab3848285016107b7565b91505092915050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b5f819050919050565b610af781610ae5565b82525050565b5f610b088383610aee565b60208301905092915050565b5f602082019050919050565b5f610b2a82610abc565b610b348185610ac6565b9350610b3f83610ad6565b805f5b83811015610b6f578151610b568882610afd565b9750610b6183610b14565b925050600181019050610b42565b5085935050505092915050565b5f6020820190508181035f830152610b948184610b20565b905092915050565b5f82905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680610c1757607f821691505b602082108103610c2a57610c29610bd3565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f60088302610c8c7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610c51565b610c968683610c51565b95508019841693508086168417925050509392505050565b5f819050919050565b5f610cd1610ccc610cc78461070e565b610cae565b61070e565b9050919050565b5f819050919050565b610cea83610cb7565b610cfe610cf682610cd8565b848454610c5d565b825550505050565b5f5f905090565b610d15610d06565b610d20818484610ce1565b505050565b5b81811015610d4357610d385f82610d0d565b600181019050610d26565b5050565b601f821115610d8857610d5981610c30565b610d6284610c42565b81016020851015610d71578190505b610d85610d7d85610c42565b830182610d25565b50505b505050565b5f82821c905092915050565b5f610da85f1984600802610d8d565b1980831691505092915050565b5f610dc08383610d99565b9150826002028217905092915050565b610dda8383610b9c565b67ffffffffffffffff811115610df357610df2610ba6565b5b610dfd8254610c00565b610e08828285610d47565b5f601f831160018114610e35575f8415610e23578287013590505b610e2d8582610db5565b865550610e94565b601f198416610e4386610c30565b5f5b82811015610e6a57848901358255600182019150602085019450602081019050610e45565b86831015610e875784890135610e83601f891682610d99565b8355505b6001600288020188555050505b50505050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610ed48261070e565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203610f0657610f05610e9d565b5b600182019050919050565b610f1a81610ae5565b82525050565b5f604082019050610f335f830185610f11565b610f406020830184610717565b9392505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f604082019050610f875f830185610717565b610f946020830184610717565b9392505050565b5f819050919050565b610fb5610fb082610ae5565b610f9b565b82525050565b5f610fc68287610fa4565b602082019150610fd68286610fa4565b602082019150610fe68285610fa4565b602082019150610ff68284610fa4565b60208201915081905095945050505050565b5f6110128261070e565b915061101d8361070e565b925082820190508082111561103557611034610e9d565b5b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f6110728261070e565b915061107d8361070e565b92508261108d5761108c61103b565b5b828204905092915050565b5f6110a28261070e565b91506110ad8361070e565b92508282026110bb8161070e565b915082820484148315176110d2576110d1610e9d565b5b5092915050565b5f6110e48285610fa4565b6020820191506110f48284610fa4565b6020820191508190509392505050565b5f61110e8261070e565b91506111198361070e565b9250826111295761112861103b565b5b828206905092915050565b5f61113e8261070e565b91506111498361070e565b925082820390508181111561116157611160610e9d565b5b9291505056fea26469706673582212209e900f14d1747552590d79f4ed67cc13e505c8f57b9a724cfe597063f757da1664736f6c634300081e0033";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deploy `MockRollup` on the given Anvil provider and return its address.
pub async fn deploy_mock_rollup(provider: &RootProvider) -> Result<Address> {
    let bytecode = alloy_primitives::hex::decode(
        MOCK_ROLLUP_BYTECODE.strip_prefix("0x").unwrap_or(MOCK_ROLLUP_BYTECODE),
    )
    .map_err(|e| eyre!("bad bytecode hex: {e}"))?;

    let tx = alloy_rpc_types::TransactionRequest {
        input: Bytes::from(bytecode).into(),
        ..Default::default()
    };

    let pending =
        provider.send_transaction(tx).await.map_err(|e| eyre!("deploy tx failed: {e}"))?;

    let receipt = pending.get_receipt().await.map_err(|e| eyre!("deploy receipt failed: {e}"))?;

    let addr =
        receipt.contract_address.ok_or_else(|| eyre!("no contract address in deploy receipt"))?;

    info!(%addr, "MockRollup deployed");
    Ok(addr)
}

/// Call `submitBlobs(batchIndex, blobHashes)` on the mock contract.
///
/// This simulates L1 `submitBlobs` and emits `BatchBlobsSubmitted` which
/// `blob.rs` filters for.
pub async fn submit_blobs(
    provider: &RootProvider,
    contract: Address,
    batch_index: u64,
    blob_hashes: Vec<B256>,
) -> Result<()> {
    let call = MockRollup::submitBlobsCall {
        batchIndex: U256::from(batch_index),
        blobHashes: blob_hashes.into_iter().map(|h| h.into()).collect(),
    };

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let pending =
        provider.send_transaction(tx).await.map_err(|e| eyre!("submitBlobs tx failed: {e}"))?;

    pending.get_receipt().await.map_err(|e| eyre!("submitBlobs receipt failed: {e}"))?;

    info!(batch_index, "submitBlobs executed");
    Ok(())
}

/// Call `acceptNextBatch(blockHeaders, expectedBlobsCount)` on the mock contract.
///
/// Emits `BatchHeadersSubmitted`.
pub async fn accept_next_batch(
    provider: &RootProvider,
    contract: Address,
    block_headers: Vec<L2BlockHeader>,
    expected_blobs_count: u64,
) -> Result<()> {
    let call = MockRollup::acceptNextBatchCall {
        blockHeaders: block_headers,
        expectedBlobsCount: U256::from(expected_blobs_count),
    };

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let pending =
        provider.send_transaction(tx).await.map_err(|e| eyre!("acceptNextBatch tx failed: {e}"))?;

    pending.get_receipt().await.map_err(|e| eyre!("acceptNextBatch receipt failed: {e}"))?;

    info!("acceptNextBatch executed");
    Ok(())
}

/// Call `preconfirmBatch(nitroVerifier, batchIndex, signature)` on the mock contract.
pub async fn preconfirm_batch(
    provider: &RootProvider,
    contract: Address,
    nitro_verifier: Address,
    batch_index: u64,
    signature: Vec<u8>,
) -> Result<()> {
    let call = MockRollup::preconfirmBatchCall {
        nitroVerifier: nitro_verifier,
        batchIndex: U256::from(batch_index),
        signature: Bytes::from(signature),
    };

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let pending =
        provider.send_transaction(tx).await.map_err(|e| eyre!("preconfirmBatch tx failed: {e}"))?;

    pending.get_receipt().await.map_err(|e| eyre!("preconfirmBatch receipt failed: {e}"))?;

    info!(batch_index, "preconfirmBatch executed");
    Ok(())
}

/// Read `batchBlobHashes(batchIndex)` from the mock contract.
pub async fn read_batch_blob_hashes(
    provider: &RootProvider,
    contract: Address,
    batch_index: u64,
) -> Result<Vec<B256>> {
    let call = MockRollup::batchBlobHashesCall { batchIndex: U256::from(batch_index) };

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let result = provider.call(tx).await.map_err(|e| eyre!("batchBlobHashes call failed: {e}"))?;

    let decoded = MockRollup::batchBlobHashesCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("decode batchBlobHashes: {e}"))?;

    Ok(decoded.into_iter().map(B256::from).collect())
}

/// Read `nextBatchIndex` from the mock contract.
pub async fn read_next_batch_index(provider: &RootProvider, contract: Address) -> Result<u64> {
    let call = MockRollup::nextBatchIndexCall {};

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let result = provider.call(tx).await.map_err(|e| eyre!("nextBatchIndex call failed: {e}"))?;

    let decoded = MockRollup::nextBatchIndexCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("decode nextBatchIndex: {e}"))?;

    Ok(decoded.to::<u64>())
}

/// Read `lastPreconfirmedBatch` from the mock contract.
pub async fn read_last_preconfirmed_batch(
    provider: &RootProvider,
    contract: Address,
) -> Result<u64> {
    let call = MockRollup::lastPreconfirmedBatchCall {};

    let tx = alloy_rpc_types::TransactionRequest {
        to: Some(contract.into()),
        input: Bytes::from(call.abi_encode()).into(),
        ..Default::default()
    };

    let result =
        provider.call(tx).await.map_err(|e| eyre!("lastPreconfirmedBatch call failed: {e}"))?;

    let decoded = MockRollup::lastPreconfirmedBatchCall::abi_decode_returns(&result)
        .map_err(|e| eyre!("decode lastPreconfirmedBatch: {e}"))?;

    Ok(decoded.to::<u64>())
}
