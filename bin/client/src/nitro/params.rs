/// The port on which the enclave listens for incoming connections.
/// The parent host connects to this port to send execution tasks (STF) via VSOCK.
pub const VSOCK_PORT: u32 = 5005;

/// Maximum allowed size for a single data frame (64 MB).
/// Acts as a security boundary to prevent memory exhaustion during stream reading.
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

/// The Reserved Context ID (CID) for the parent host.
/// In the Nitro Enclave architecture, the host is always reachable at CID 3.
pub const HOST_CID: u32 = 3;

/// The port on the parent host where the vsock-proxy is running.
/// This proxy forwards the enclave's encrypted traffic to the actual AWS KMS endpoint.
pub const KMS_PORT: u32 = 8000;

/// The AWS Region where the KMS service is located.
pub const REGION: &str = "us-east-1";

/// The DNS hostname for the AWS KMS endpoint.
pub const KMS_HOST: &str = "kms.us-east-1.amazonaws.com";

/// Required Content-Type header for AWS JSON RPC requests.
pub const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// The X-Amz-Target header value for generating random bytes from KMS.
/// Used as a second independent entropy source alongside NSM GetRandom.
pub const TARGET_GENERATE_RANDOM: &str = "TrentService.GenerateRandom";
