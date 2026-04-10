use alloy_consensus::TxReceipt;
use alloy_primitives::{b256, Address, FixedBytes, Keccak256, LogData, B256};
use alloy_sol_types::sol;
use bincode::Error;
use reth_execution_types::ExecutionOutcome;

sol! {
    struct Log{
        address address;
        uint256[] topics;
        bytes data;
    }

    struct SentMessage {
        uint256 value;
        uint256 nonce;
        bytes32 messageHash;
        bytes data;
    }
}

const ZERO_BYTES_HASH: B256 =
    b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

#[derive(Debug)]
pub struct BridgeHashes {
    pub withdrawal_hash: B256,
    pub deposit_hash: B256,
}

pub(crate) struct BridgeInfo {
    pub bridge_address: Address,
    pub withdrawal_topic: B256,
    pub rollback_topic: B256,
    pub deposit_topic: B256,
}

impl BridgeInfo {
    pub(crate) fn calculate_bridge_hashes<T: TxReceipt<Log = alloy_primitives::Log>>(
        &self,
        execution_outcome: &ExecutionOutcome<T>,
    ) -> Result<BridgeHashes, Error> {
        Ok(BridgeHashes {
            withdrawal_hash: execution_outcome.calculate_withdrawal_root(
                &self.bridge_address,
                &self.withdrawal_topic,
                &self.rollback_topic,
            )?,
            deposit_hash: execution_outcome
                .calculate_deposit_hash(&self.bridge_address, &self.deposit_topic)?,
        })
    }
}

impl From<&alloy_primitives::Log> for Log {
    fn from(value: &alloy_primitives::Log) -> Self {
        Log {
            address: (&*value.address.0).into(),
            topics: value
                .data
                .topics()
                .iter()
                .map(|topic| FixedBytes::new(topic.0).into())
                .collect(),
            data: value.data.data.to_vec().into(),
        }
    }
}

fn merkle_root(mut leaves: Vec<B256>) -> B256 {
    if leaves.is_empty() {
        return ZERO_BYTES_HASH;
    }

    while leaves.len() > 1 {
        if !leaves.len().is_multiple_of(2) {
            leaves.push(*leaves.last().unwrap());
        }

        for i in 0..leaves.len() / 2 {
            let mut hasher = Keccak256::new();
            hasher.update(leaves[i * 2]);
            hasher.update(leaves[i * 2 + 1]);
            leaves[i] = hasher.finalize();
        }
        leaves.truncate(leaves.len() / 2);
    }

    leaves[0]
}

pub(crate) trait CalculateEventsHash {
    fn calculate_deposit_hash(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
    ) -> Result<B256, Error>;

    fn calculate_withdrawal_root(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
        rollback_topic: &B256,
    ) -> Result<B256, Error>;

    fn find_receipt_log(&self, bridge_address: &Address, send_topic: &B256) -> Vec<&LogData>;
}

// see bridge contract for details: https://github.com/fluentlabs-xyz/solidity-contracts/blob/devel/contracts/interfaces/IFluentBridge.sol#L48
// cast sig-event "ReceivedMessage(bytes32,bool,bytes)"
const RECEIVE_EVENT_MESSAGE_HASH_OFFSET: usize = 0;

// cast sig-event "SentMessage(address,address,uint256,uint256,uint256,uint256,bytes32,bytes)"
// indexed: sender=topic[1], to=topic[2] → not in data
// data: value(0) | chainId(32) | blockNumber(64) | nonce(96) | messageHash(128)
const SEND_EVENT_MESSAGE_HASH_OFFSET: usize = 128;

// cast sig-event "RollbackMessage(bytes32,uint256)"
// data: messageHash(0) | blockNumber(32)
const ROLLBACK_EVENT_MESSAGE_HASH_OFFSET: usize = 0;

impl<T: TxReceipt<Log = alloy_primitives::Log>> CalculateEventsHash for ExecutionOutcome<T> {
    fn calculate_deposit_hash(
        &self,
        bridge_address: &Address,
        receive_topic: &B256,
    ) -> Result<B256, Error> {
        let deposit_logs = self.find_receipt_log(bridge_address, receive_topic);
        let message_hashes = deposit_logs
            .into_iter()
            .filter(|log_data| log_data.data.len() >= RECEIVE_EVENT_MESSAGE_HASH_OFFSET + 32)
            .map(|log_data| {
                let message_hash: [u8; 32] = log_data.data
                    [RECEIVE_EVENT_MESSAGE_HASH_OFFSET..RECEIVE_EVENT_MESSAGE_HASH_OFFSET + 32]
                    .try_into()
                    .unwrap();
                B256::from(message_hash)
            })
            .collect::<Vec<_>>();

        let mut hasher = Keccak256::new();

        for message_hash in message_hashes {
            hasher.update(message_hash);
        }

        Ok(hasher.finalize())
    }

    fn calculate_withdrawal_root(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
        rollback_topic: &B256,
    ) -> Result<B256, Error> {
        let message_hashes = self
            .receipts
            .iter()
            .flat_map(|receipt| receipt.iter().filter(TxReceipt::status).flat_map(TxReceipt::logs))
            .filter(|log| &log.address == bridge_address)
            .filter_map(|log| {
                let topic = log.data.topics().first()?;
                if topic == send_topic {
                    if log.data.data.len() >= SEND_EVENT_MESSAGE_HASH_OFFSET + 32 {
                        let hash: [u8; 32] = log.data.data
                            [SEND_EVENT_MESSAGE_HASH_OFFSET..SEND_EVENT_MESSAGE_HASH_OFFSET + 32]
                            .try_into()
                            .unwrap();
                        Some(B256::from(hash))
                    } else {
                        None
                    }
                } else if topic == rollback_topic {
                    if log.data.data.len() >= ROLLBACK_EVENT_MESSAGE_HASH_OFFSET + 32 {
                        let hash: [u8; 32] = log.data.data[ROLLBACK_EVENT_MESSAGE_HASH_OFFSET
                            ..ROLLBACK_EVENT_MESSAGE_HASH_OFFSET + 32]
                            .try_into()
                            .unwrap();
                        Some(B256::from(hash))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(merkle_root(message_hashes))
    }

    fn find_receipt_log(&self, bridge_address: &Address, send_topic: &B256) -> Vec<&LogData> {
        self.receipts
            .iter()
            .flat_map(|receipt| receipt.iter().filter(TxReceipt::status).flat_map(TxReceipt::logs))
            .filter(|log| {
                &log.address == bridge_address
                    && log.data.topics().first().map(|topic| topic == send_topic).unwrap_or(false)
            })
            .map(|log| &log.data)
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxType;
    use alloy_primitives::{b256, hex, Address, Bytes, Keccak256, Log, LogData, B256, U256};
    use alloy_sol_types::SolValue;
    use reth_execution_types::ExecutionOutcome;

    use crate::events_hash::{CalculateEventsHash, Log as EncodeLog, ZERO_BYTES_HASH};

    #[test]
    fn abi_encode() {
        let send_event_topic = U256::from(0xcccc);
        let log = EncodeLog {
            address: [0x0a; 20].into(),
            topics: vec![send_event_topic],
            data: [0xbb; 32].into(),
        };

        assert_eq!(
            log.abi_encode(),
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10, 10, 10, 10,
                10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 187, 187, 187, 187, 187, 187
            ]
        );

        assert_eq!(
            log.abi_encode_packed(),
            vec![
                10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 204, 204, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187, 187,
                187, 187
            ]
        );
    }

    #[test]
    fn test_deposit_event_hash() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![vec![reth_ethereum_primitives::Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![
                Log {
                    address: Default::default(),
                    data: LogData::new(vec![], Bytes::new()).unwrap(),
                },
                Log {
                    address: bridge_address,
                    data: LogData::new(
                        vec![send_event_topic, B256::default()],
                        Bytes::from([0x99; 64]),
                    )
                    .unwrap(),
                },
            ],
        }]];

        let expected_data =
            hex!("0x9999999999999999999999999999999999999999999999999999999999999999");

        let mut hasher = Keccak256::new();
        hasher.update(expected_data);

        let expected_hash = hasher.finalize();

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_any_deposit_events_hash() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![
            vec![
                reth_ethereum_primitives::Receipt {
                    tx_type: TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![
                        Log {
                            address: Default::default(),
                            data: LogData::new(vec![], Bytes::new()).unwrap(),
                        },
                        Log {
                            address: bridge_address,
                            data: LogData::new(
                                vec![send_event_topic, B256::default()],
                                Bytes::from([98; 64]),
                            )
                            .unwrap(),
                        },
                    ],
                },
                reth_ethereum_primitives::Receipt {
                    tx_type: TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![
                        Log {
                            address: Default::default(),
                            data: LogData::new(vec![], Bytes::new()).unwrap(),
                        },
                        Log {
                            address: bridge_address,
                            data: LogData::new(
                                vec![send_event_topic, B256::default()],
                                Bytes::from([99; 64]),
                            )
                            .unwrap(),
                        },
                    ],
                },
            ],
            vec![reth_ethereum_primitives::Receipt {
                tx_type: TxType::Eip1559,
                success: true,
                cumulative_gas_used: 0,
                logs: vec![Log {
                    address: bridge_address,
                    data: LogData::new(
                        vec![send_event_topic, B256::default()],
                        Bytes::from([100; 32]),
                    )
                    .unwrap(),
                }],
            }],
        ];

        let expected_data = hex!("0x626262626262626262626262626262626262626262626262626262626262626263636363636363636363636363636363636363636363636363636363636363636464646464646464646464646464646464646464646464646464646464646464");

        let mut hasher = Keccak256::new();
        hasher.update(expected_data);

        let expected_hash = hasher.finalize();

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_empty_deposit_hash() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![
            vec![
                reth_ethereum_primitives::Receipt::default(),
                reth_ethereum_primitives::Receipt::default(),
            ],
            vec![
                reth_ethereum_primitives::Receipt::default(),
                reth_ethereum_primitives::Receipt::default(),
            ],
        ];

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, ZERO_BYTES_HASH);
    }

    #[test]
    fn test_empty_withdrawal_root() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);
        let rollback_event_topic = B256::from([0x1b; 32]);

        execution_outcome.receipts = vec![
            vec![
                reth_ethereum_primitives::Receipt::default(),
                reth_ethereum_primitives::Receipt::default(),
            ],
            vec![
                reth_ethereum_primitives::Receipt::default(),
                reth_ethereum_primitives::Receipt::default(),
            ],
        ];

        let actual_hash = execution_outcome
            .calculate_withdrawal_root(&bridge_address, &send_event_topic, &rollback_event_topic)
            .unwrap();

        assert_eq!(actual_hash, ZERO_BYTES_HASH);
    }

    #[test]
    fn test_deposit_hash() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        let event_data = hex!("0xb054bbc29d2e7acbd3e724ebee9a9b350202ede8800adf450cd7cc66d011bc7a0000000000000000000000000000000000000000000000000000000000000001");

        execution_outcome.receipts = vec![
            vec![
                reth_ethereum_primitives::Receipt {
                    tx_type: Default::default(),
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![Log {
                        address: bridge_address,
                        data: LogData::new(vec![send_event_topic], Bytes::from(event_data))
                            .unwrap(),
                    }],
                },
                reth_ethereum_primitives::Receipt::default(),
            ],
            vec![
                reth_ethereum_primitives::Receipt::default(),
                reth_ethereum_primitives::Receipt::default(),
            ],
        ];

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        let expected_deposit_hash: B256 =
            b256!("0x027916995b58e921b14738f7dae4eeab4cfb30e2022d6c9a608c62a9d18d934e");

        assert_eq!(actual_hash, expected_deposit_hash);
    }

    #[test]
    fn test_withdrawal_root() {
        let mut execution_outcome =
            ExecutionOutcome::<reth_ethereum_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);
        let rollback_event_topic = B256::from([0x1b; 32]);
        let event_data =  hex!("0x00000000000000000000000000000000000000000000000000000000000007d00000000000000000000000000000000000000000000000000000000000000000835612469dd5d58ef5be0da80c826de8354bbdd63eec7aea2dcca10ab8c0ff73000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000050102030405000000000000000000000000000000000000000000000000000000");
        let event_data2 = hex!("0x00000000000000000000000000000000000000000000000000000000000009d000000000000000000000000000000000000000000000000000000000000000007e3a41a1eaf8f064503f94e4090673e401318e9c6f22ee1002084d58465b4a11000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000051122334455000000000000000000000000000000000000000000000000000000");

        execution_outcome.receipts = vec![
            vec![
                reth_ethereum_primitives::Receipt {
                    tx_type: Default::default(),
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![Log {
                        address: bridge_address,
                        data: LogData::new(vec![send_event_topic], Bytes::from(event_data))
                            .unwrap(),
                    }],
                },
                reth_ethereum_primitives::Receipt::default(),
            ],
            vec![
                reth_ethereum_primitives::Receipt {
                    tx_type: Default::default(),
                    success: true,
                    cumulative_gas_used: 0,
                    logs: vec![Log {
                        address: bridge_address,
                        data: LogData::new(vec![send_event_topic], Bytes::from(event_data2))
                            .unwrap(),
                    }],
                },
                reth_ethereum_primitives::Receipt::default(),
            ],
        ];

        let actual_hash = execution_outcome
            .calculate_withdrawal_root(&bridge_address, &send_event_topic, &rollback_event_topic)
            .unwrap();
        let expected_withdrawal_hash: B256 =
            b256!("0x458b30c2d72bfd2c6317304a4594ecbafe5f729d3111b65fdc3a33bd48e5432d");

        assert_eq!(actual_hash, expected_withdrawal_hash);
    }
}
