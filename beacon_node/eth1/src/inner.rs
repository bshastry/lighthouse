use crate::service::endpoint_from_config;
use crate::Config;
use crate::{
    block_cache::{BlockCache, Eth1Block},
    deposit_cache::{DepositCache, SszDepositCache, SszDepositCacheV13},
};
use execution_layer::HttpJsonRpc;
use parking_lot::RwLock;
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use types::{ChainSpec, DepositTreeSnapshot, Eth1Data};

// Define "legacy" implementations of `Option<u64>` which use four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_u64, u64);

#[derive(Default)]
pub struct DepositUpdater {
    pub cache: DepositCache,
    pub last_processed_block: Option<u64>,
}

impl DepositUpdater {
    pub fn new(deposit_contract_deploy_block: u64) -> Self {
        let cache = DepositCache::new(deposit_contract_deploy_block);
        DepositUpdater {
            cache,
            last_processed_block: None,
        }
    }

    pub fn from_snapshot(
        deposit_contract_deploy_block: u64,
        snapshot: &DepositTreeSnapshot,
    ) -> Result<Self, String> {
        let last_processed_block = Some(snapshot.execution_block_height);
        Ok(Self {
            cache: DepositCache::from_deposit_snapshot(deposit_contract_deploy_block, snapshot)?,
            last_processed_block,
        })
    }
}

pub struct Inner {
    pub block_cache: RwLock<BlockCache>,
    pub deposit_cache: RwLock<DepositUpdater>,
    pub endpoint: HttpJsonRpc,
    // this gets set to Some(Eth1Data) when the deposit finalization conditions are met
    pub to_finalize: RwLock<Option<Eth1Data>>,
    pub config: RwLock<Config>,
    pub remote_head_block: RwLock<Option<Eth1Block>>,
    pub spec: ChainSpec,
}

impl Inner {
    /// Prunes the block cache to `self.target_block_cache_len`.
    ///
    /// Is a no-op if `self.target_block_cache_len` is `None`.
    pub fn prune_blocks(&self) {
        if let Some(block_cache_truncation) = self.config.read().block_cache_truncation {
            self.block_cache.write().truncate(block_cache_truncation);
        }
    }

    /// Encode the eth1 block and deposit cache as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let ssz_eth1_cache = SszEth1Cache::from_inner(self);
        ssz_eth1_cache.as_ssz_bytes()
    }

    /// Recover `Inner` given byte representation of eth1 deposit and block caches.
    pub fn from_bytes(bytes: &[u8], config: Config, spec: ChainSpec) -> Result<Self, String> {
        SszEth1Cache::from_ssz_bytes(bytes)
            .map_err(|e| format!("Ssz decoding error: {:?}", e))?
            .to_inner(config, spec)
            .map(|inner| {
                inner.block_cache.write().rebuild_by_hash_map();
                inner
            })
    }

    /// Returns a reference to the specification.
    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }
}

pub type SszEth1Cache = SszEth1CacheV13;

#[superstruct(
    variants(V13),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszEth1Cache {
    pub block_cache: BlockCache,
    pub deposit_cache: SszDepositCacheV13,
    #[ssz(with = "four_byte_option_u64")]
    pub last_processed_block: Option<u64>,
}

impl SszEth1Cache {
    pub fn from_inner(inner: &Inner) -> Self {
        let deposit_updater = inner.deposit_cache.read();
        let block_cache = inner.block_cache.read();
        Self {
            block_cache: (*block_cache).clone(),
            deposit_cache: SszDepositCache::from_deposit_cache(&deposit_updater.cache),
            last_processed_block: deposit_updater.last_processed_block,
        }
    }

    pub fn to_inner(&self, config: Config, spec: ChainSpec) -> Result<Inner, String> {
        Ok(Inner {
            block_cache: RwLock::new(self.block_cache.clone()),
            deposit_cache: RwLock::new(DepositUpdater {
                cache: self.deposit_cache.to_deposit_cache()?,
                last_processed_block: self.last_processed_block,
            }),
            endpoint: endpoint_from_config(&config)
                .map_err(|e| format!("Failed to create endpoint: {:?}", e))?,
            to_finalize: RwLock::new(None),
            // Set the remote head_block zero when creating a new instance. We only care about
            // present and future eth1 nodes.
            remote_head_block: RwLock::new(None),
            config: RwLock::new(config),
            spec,
        })
    }
}
