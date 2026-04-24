use std::time::Duration;

use alloy_json_rpc::RpcError;
use alloy_provider::{Network, RootProvider};
use alloy_rpc_client::RpcClient;
use alloy_transport::{
    layers::{RateLimitRetryPolicy, RetryBackoffLayer, RetryPolicy},
    TransportError, TransportErrorKind,
};
use alloy_transport_http::{reqwest, Http};
use url::Url;

/// Per-request timeout for every JSON-RPC call. Generous enough for
/// `eth_getBlockByNumber` on a loaded archive node; tight enough that a
/// dead TCP socket does not hang the caller indefinitely. The existing
/// `RetryBackoffLayer` will retry on timeout, so legitimate slow calls
/// succeed on a later attempt.
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn create_provider<N: Network>(rpc_url: Url) -> eyre::Result<RootProvider<N>> {
    let http_client = reqwest::Client::builder()
        .timeout(RPC_CALL_TIMEOUT)
        .connect_timeout(RPC_CONNECT_TIMEOUT)
        .pool_max_idle_per_host(4)
        .build()
        .map_err(|e| eyre::eyre!("failed to build reqwest client: {e}"))?;
    let transport = Http::with_client(http_client, rpc_url);
    let retry_layer =
        RetryBackoffLayer::new_with_policy(5, 1000, 30000, ServerErrorRetryPolicy::default());
    let client = RpcClient::builder().layer(retry_layer).transport(transport, false);
    Ok(RootProvider::new(client))
}

#[derive(Debug, Copy, Clone, Default)]
struct ServerErrorRetryPolicy(RateLimitRetryPolicy);

impl RetryPolicy for ServerErrorRetryPolicy {
    fn should_retry(&self, error: &TransportError) -> bool {
        if self.0.should_retry(error) {
            return true;
        }

        if let RpcError::Transport(TransportErrorKind::HttpError(http_error)) = error {
            if http_error.status >= 500 && http_error.status < 600 {
                return true;
            }
        }

        false
    }

    fn backoff_hint(&self, error: &TransportError) -> Option<std::time::Duration> {
        self.0.backoff_hint(error)
    }
}
