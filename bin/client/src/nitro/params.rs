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

/// The Unique Identifier (UUID or ARN) of the AWS KMS Customer Master Key (CMK).
/// This key controls the encryption and decryption of the enclave's local secrets.
pub const KEY_ID: &str = "e3e3147b-f94a-4127-a845-a082e6cc8448";

/// The AWS Region where the KMS service is located.
pub const REGION: &str = "us-east-1";

/// The DNS hostname for the AWS KMS endpoint.
/// Necessary for establishing a TLS tunnel and for the SNI (Server Name Indication) header.
pub const KMS_HOST: &str = "kms.us-east-1.amazonaws.com";

/// Required Content-Type header for AWS JSON RPC requests.
/// Version 1.1 is the standard for the Key Management Service (KMS) API.
pub const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// The X-Amz-Target header value for generating a new Data Key.
/// Used during the initial setup phase ("First Run") of the enclave.
pub const TARGET_GENERATE_DATA_KEY: &str = "TrentService.GenerateDataKey";

/// The X-Amz-Target header value for decrypting an existing Data Key.
/// Used for key restoration on "Subsequent Runs" via cryptographic attestation.
pub const TARGET_DECRYPT: &str = "TrentService.Decrypt";

/// The X-Amz-Target header value for decrypting an existing Data Key.
/// Used for key restoration on "Subsequent Runs" via cryptographic attestation.
pub const TARGET_ENCRYPT: &str = "TrentService.Encrypt";
