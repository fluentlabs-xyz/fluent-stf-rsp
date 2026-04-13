use std::{
    cell::{Cell, RefCell},
    fmt,
};

use alloy_consensus::Header;
use alloy_primitives::{map::HashMap, U256};
use reth_provider::{
    BlockReader, HeaderProvider, StateProofProvider, StateProviderBox, StateProviderFactory,
};
use reth_storage_errors::{db::DatabaseError, provider::ProviderError};
use reth_trie::{HashedPostState, KeccakKeyHasher, MultiProofTargets, TrieInput};
use revm_database::BundleState;
use revm_database_interface::DatabaseRef;
use revm_primitives::{map::B256Set, Address, B256, KECCAK_EMPTY};
use revm_state::{AccountInfo, Bytecode};
use rsp_mpt::EthereumState;
use tracing::debug;

use crate::RpcDbError;

/// Database that reads state directly from a reth provider (ExEx context).
///
/// Key differences from `BasicRpcDb`:
/// - No RPC — reads state directly via `StateProviderFactory`.
/// - Provider checks in-memory (blockchain tree) first, then MDBX.
/// - `state()` uses two `multiproof()` calls instead of 2N `get_proof`:
///   - before-multiproof: historical provider (block N-1), single trie walk with changesets.
///   - after-multiproof: latest provider (block N), single walk over current trie — fast.
///
/// # Thread safety
///
/// This type is single-threaded by design: created, used, and dropped within
/// one `execute_exex` call on one thread. Interior mutability is via
/// `RefCell`/`Cell` — zero runtime cost compared to any locking primitive.
///
/// # Account existence semantics
///
/// `accounts` map stores `Option<AccountInfo>`:
/// - `Some(info)` — account exists at block N-1.
/// - `None` — account was queried but does not exist (needed for absence proof).
///
/// This is critical for correct `BundleState` generation: revm must see
/// `None` from `basic_ref` for non-existent accounts to produce `Created`
/// (not `Changed`) entries in the bundle state.
pub struct ExExDb<F> {
    pub provider_factory: F,
    pub block_number: u64,
    pub state_root: B256,
    /// Parent block hash — used for hash-based state lookups that correctly
    /// handle reorgs by checking the in-memory blockchain tree first.
    parent_hash: B256,
    /// Historical state provider for block N-1, created once in constructor.
    before_provider: StateProviderBox,
    accounts: RefCell<HashMap<Address, Option<AccountInfo>>>,
    storage: RefCell<HashMap<Address, HashMap<U256, U256>>>,
    oldest_ancestor: Cell<u64>,
}

impl<F> ExExDb<F>
where
    F: StateProviderFactory + HeaderProvider<Header = Header> + BlockReader + Clone,
{
    /// Creates a new `ExExDb`.
    ///
    /// Tries `state_by_block_hash(parent_hash)` first (handles reorgs via
    /// in-memory blockchain tree). Falls back to `history_by_block_number(N-1)`
    /// which uses MDBX changesets — works during pipeline sync where the
    /// blockchain tree is empty but changesets are committed.
    pub fn new(
        provider_factory: F,
        block_number: u64,
        parent_hash: B256,
        state_root: B256,
    ) -> Result<Self, RpcDbError> {
        let before_provider = provider_factory
            .state_by_block_hash(parent_hash)
            .or_else(|_| {
                debug!(
                    block_number,
                    %parent_hash,
                    "state_by_block_hash failed, falling back to history_by_block_number"
                );
                provider_factory.history_by_block_number(block_number.saturating_sub(1))
            })
            .map_err(RpcDbError::from)?;

        Ok(Self {
            provider_factory,
            block_number,
            state_root,
            parent_hash,
            before_provider,
            accounts: RefCell::new(HashMap::with_hasher(Default::default())),
            storage: RefCell::new(HashMap::with_hasher(Default::default())),
            oldest_ancestor: Cell::new(block_number),
        })
    }

    /// Fetches account info from the before-state (block N-1).
    ///
    /// Returns `None` if the account does not exist — this is critical for
    /// correct `BundleState` semantics (`Created` vs `Changed`).
    pub fn fetch_account_info(&self, address: Address) -> Result<Option<AccountInfo>, RpcDbError> {
        debug!("fetching account info for address: {}", address);

        let account = self
            .before_provider
            .basic_account(&address)
            .map_err(|e| RpcDbError::GetProofError(address, e.to_string()))?;

        let result = match account {
            Some(account) => {
                let code_hash = if account.bytecode_hash.unwrap_or(KECCAK_EMPTY) == B256::ZERO {
                    KECCAK_EMPTY
                } else {
                    account.bytecode_hash.unwrap_or(KECCAK_EMPTY)
                };

                let bytecode = self
                    .before_provider
                    .bytecode_by_hash(&code_hash)
                    .map_err(|e| RpcDbError::GetCodeError(address, e.to_string()))?
                    .unwrap_or_default();

                Some(AccountInfo {
                    nonce: account.nonce,
                    balance: account.balance,
                    code_hash,
                    code: Some(bytecode.0),
                    account_id: None,
                })
            }
            None => None,
        };

        self.accounts.borrow_mut().insert(address, result.clone());

        Ok(result)
    }

    pub fn fetch_storage_at(&self, address: Address, index: U256) -> Result<U256, RpcDbError> {
        debug!("fetching storage value at address: {}, index: {}", address, index);

        let value = self
            .before_provider
            .storage(address, B256::from(index))
            .map_err(|e| RpcDbError::GetStorageError(address, index, e.to_string()))?
            .unwrap_or_default();

        self.storage.borrow_mut().entry(address).or_default().insert(index, value);

        Ok(value)
    }

    /// Looks up bytecode by hash.
    ///
    /// Called by revm for `EXTCODECOPY`/`EXTCODESIZE` on warm accounts whose
    /// code was evicted from `CacheDB`.
    pub fn fetch_code_by_hash(&self, code_hash: B256) -> Result<Bytecode, RpcDbError> {
        if code_hash == KECCAK_EMPTY || code_hash == B256::ZERO {
            return Ok(Bytecode::default());
        }

        let bytecode = self
            .before_provider
            .bytecode_by_hash(&code_hash)
            .map_err(|e| RpcDbError::GetCodeError(Address::ZERO, e.to_string()))?
            .ok_or_else(|| {
                RpcDbError::GetCodeError(
                    Address::ZERO,
                    format!("bytecode not found for hash {code_hash}"),
                )
            })?;

        Ok(bytecode.0)
    }

    pub fn fetch_block_hash(&self, number: u64) -> Result<B256, RpcDbError> {
        debug!("fetching block hash for block number: {}", number);

        let hash = self
            .provider_factory
            .block_hash(number)
            .map_err(|e| RpcDbError::GetBlockError(number, e.to_string()))?
            .ok_or(RpcDbError::BlockNotFound(number))?;

        let current = self.oldest_ancestor.get();
        self.oldest_ancestor.set(number.min(current));

        Ok(hash)
    }

    /// Build before-multiproof targets: all touched accounts + their storage
    /// from both the DB access tracker and the execution bundle state.
    fn get_targets(&self, bundle_state: &BundleState) -> MultiProofTargets {
        let accounts = self.accounts.borrow();
        let storage = self.storage.borrow();

        let mut targets: HashMap<B256, B256Set> = HashMap::with_hasher(Default::default());

        // All addresses accessed during execution (including absent ones).
        for &address in accounts.keys().chain(storage.keys()) {
            let hashed_address = alloy_primitives::keccak256(address);
            let entry = targets.entry(hashed_address).or_default();

            if let Some(storage_map) = storage.get(&address) {
                for key in storage_map.keys() {
                    let hashed_key = alloy_primitives::keccak256(B256::from(*key));
                    entry.insert(hashed_key);
                }
            }
        }

        // Also include storage slots written by execution but not necessarily
        // read (write-only slots).
        for (address, account) in &bundle_state.state {
            let hashed_address = alloy_primitives::keccak256(address);
            let entry = targets.entry(hashed_address).or_default();

            for key in account.storage.keys() {
                let hashed_key = alloy_primitives::keccak256(B256::from(*key));
                entry.insert(hashed_key);
            }
        }

        MultiProofTargets::from_iter(targets)
    }

    pub fn state(&self, bundle_state: &BundleState) -> Result<EthereumState, RpcDbError> {
        tracing::info!("generating state via before + after multiproofs");

        let before_targets = self.get_targets(bundle_state);
        // multiproof() needs its own provider — it opens internal cursors
        // that differ from basic_account/storage access patterns.
        // Uses hash-based lookup for reorg safety (same as constructor).
        let before_provider = self
            .provider_factory
            .state_by_block_hash(self.parent_hash)
            .or_else(|_| {
                self.provider_factory.history_by_block_number(self.block_number.saturating_sub(1))
            })
            .map_err(RpcDbError::from)?;
        let before_multiproof = before_provider
            .multiproof(TrieInput::default(), before_targets)
            .map_err(|e| RpcDbError::GetProofError(Address::ZERO, e.to_string()))?;

        // ── After-multiproof via overlay ──────────────────────────
        // Instead of history_by_block_number(N) (requires history indices),
        // reuse the before-provider (block N-1) and prepend the execution's
        // BundleState as a HashedPostState overlay. This gives the trie walker
        // the post-execution state without needing a separate provider.
        let after_targets = self.get_targets(bundle_state);
        let after_base_provider = self
            .provider_factory
            .state_by_block_hash(self.parent_hash)
            .or_else(|_| {
                self.provider_factory.history_by_block_number(self.block_number.saturating_sub(1))
            })
            .map_err(RpcDbError::from)?;
        let hashed_post_state =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&bundle_state.state);
        let mut after_input = TrieInput::default();
        after_input.prepend(hashed_post_state);
        let after_multiproof = after_base_provider
            .multiproof(after_input, after_targets)
            .map_err(|e| RpcDbError::GetProofError(Address::ZERO, e.to_string()))?;

        let state = EthereumState::from_transition_multiproofs(
            self.state_root,
            &before_multiproof,
            &after_multiproof,
        )?;

        Ok(state)
    }

    /// Collects unique bytecodes from all fetched accounts.
    ///
    /// Uses `code_hash` from `AccountInfo` for deduplication instead of
    /// re-hashing via `hash_slow()` — O(1) per account vs O(code_len).
    pub fn bytecodes(&self) -> Vec<Bytecode> {
        let accounts = self.accounts.borrow();

        let mut seen = B256Set::default();
        accounts
            .values()
            .filter_map(|opt| opt.as_ref())
            .filter_map(|account| {
                let hash = account.code_hash;
                if hash == KECCAK_EMPTY || hash == B256::ZERO || !seen.insert(hash) {
                    return None;
                }
                account.code.clone()
            })
            .collect()
    }

    /// Fetches ancestor headers from `oldest_ancestor` up to (but NOT
    /// including) the current block. The current block's header is already
    /// in `ClientExecutorInput::current_block` — no need to duplicate it.
    ///
    /// Returns headers in reverse order: parent (block N-1) at index 0.
    pub fn ancestor_headers(&self) -> Result<Vec<Header>, RpcDbError> {
        let oldest_ancestor = self.oldest_ancestor.get();
        let end = self.block_number; // exclusive — don't include current block

        if oldest_ancestor >= end {
            // At minimum we need the parent header (provides parent state root).
            let header = self
                .provider_factory
                .header_by_number(self.block_number - 1)
                .map_err(|e| RpcDbError::GetBlockError(self.block_number - 1, e.to_string()))?
                .ok_or(RpcDbError::BlockNotFound(self.block_number - 1))?;
            return Ok(vec![header]);
        }

        tracing::info!(
            "fetching {} ancestor headers ({}..{})",
            end - oldest_ancestor,
            oldest_ancestor,
            end - 1,
        );

        let mut ancestor_headers = Vec::with_capacity((end - oldest_ancestor) as usize);
        // Most recent first — parent at index 0.
        for height in (oldest_ancestor..end).rev() {
            let header = self
                .provider_factory
                .header_by_number(height)
                .map_err(|e| RpcDbError::GetBlockError(height, e.to_string()))?
                .ok_or(RpcDbError::BlockNotFound(height))?;

            ancestor_headers.push(header);
        }

        Ok(ancestor_headers)
    }
}

impl<F> fmt::Debug for ExExDb<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExExDb")
            .field("block_number", &self.block_number)
            .field("state_root", &self.state_root)
            .field("oldest_ancestor", &self.oldest_ancestor.get())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// revm DatabaseRef implementation
// ---------------------------------------------------------------------------

impl<F> DatabaseRef for ExExDb<F>
where
    F: StateProviderFactory + HeaderProvider<Header = Header> + BlockReader + Clone,
{
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.fetch_account_info(address)
            .map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.fetch_code_by_hash(code_hash)
            .map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.fetch_storage_at(address, index)
            .map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.fetch_block_hash(number)
            .map_err(|e| ProviderError::Database(DatabaseError::Other(e.to_string())))
    }
}
