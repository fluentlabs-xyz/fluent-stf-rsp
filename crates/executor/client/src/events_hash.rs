use alloy_consensus::TxReceipt;
use alloy_primitives::{b256, Address, Keccak256, LogData, B256};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolType, SolValue};
use bincode::Error;
use reth_execution_types::ExecutionOutcome;
use std::io::Bytes;

sol! {
    struct Log{
        address address;
        uint256[] topics;
        bytes data;
    }
}

sol! {
    struct SentMessage {
        uint256 value;
        uint256 nonce;
        bytes32 messageHash;
        bytes data;
    }
}

static ZERO_BYTES_HASH: B256 =
    b256!("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

pub struct BridgeHashes {
    pub withdrawal_hash: B256,
    pub deposit_hash: B256,
}

pub struct BridgeInfo {
    pub address: Address,
    pub withdrawal_topic: B256,
    pub deposit_topic: B256,
}

impl BridgeInfo {
    pub fn calculate_bridge_hashes<T: TxReceipt<Log = alloy_primitives::Log>>(
        &self,
        execution_outcome: &ExecutionOutcome<T>,
    ) -> Result<BridgeHashes, Error> {
        Ok(BridgeHashes {
            withdrawal_hash: execution_outcome
                .calculate_deposit_hash(&self.address, &self.withdrawal_topic)?,
            deposit_hash: execution_outcome
                .calculate_deposit_hash(&self.address, &self.deposit_topic)?,
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
                .into_iter()
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
        if leaves.len() % 2 != 0 {
            leaves.push(leaves.last().unwrap().clone());
        }

        for i in (0..leaves.len()) {
            let mut hasher = Keccak256::new();
            hasher.update(&leaves[i * 2]);
            hasher.update(&leaves[i * 2 + 1]);
            leaves[i] = hasher.finalize();
        }
    }

    leaves[0]
}

pub trait CalculateEventsHash {
    fn calculate_deposit_hash(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
    ) -> Result<B256, Error>;

    fn calculate_withdrawal_root(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
    ) -> Result<B256, Error>;

    fn find_receipt_log(&self, bridge_address: &Address, send_topic: &B256) -> Vec<&LogData>;
}

const RECEIVE_EVENT_MESSAGE_HASH_OFFSET: usize = 0;
const SEND_EVENT_MESSAGE_HASH_OFFSET: usize = 64;

impl<T: TxReceipt<Log = alloy_primitives::Log>> CalculateEventsHash for ExecutionOutcome<T> {
    fn calculate_deposit_hash(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
    ) -> Result<B256, Error> {
        let deposit_logs = self.find_receipt_log(bridge_address, send_topic);
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
            hasher.update(&message_hash);
        }

        Ok(hasher.finalize())
    }

    fn calculate_withdrawal_root(
        &self,
        bridge_address: &Address,
        send_topic: &B256,
    ) -> Result<B256, Error> {
        let withdrawal_logs = self.find_receipt_log(bridge_address, send_topic);
        let message_hashes = withdrawal_logs
            .into_iter()
            .filter(|log_data| log_data.data.len() >= SEND_EVENT_MESSAGE_HASH_OFFSET + 32)
            .map(|log_data| {
                let message_hash: [u8; 32] = log_data.data
                    [SEND_EVENT_MESSAGE_HASH_OFFSET..SEND_EVENT_MESSAGE_HASH_OFFSET + 32]
                    .try_into()
                    .unwrap();
                B256::from(message_hash)
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
                    && log.data.topics().get(0).map(|topic| topic == send_topic).unwrap_or(false)
            })
            .map(|log| &log.data)
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxType;
    use alloy_primitives::U256;
    use alloy_primitives::{Address, Bytes, Keccak256, Log, LogData, B256};
    use alloy_sol_types::SolValue;
    use reth_execution_types::ExecutionOutcome;

    use crate::events_hash::{CalculateEventsHash, Log as EncodeLog, ZERO_BYTES_HASH};

    #[test]
    fn abi_encode() {
        let send_event_topic = U256::from(0xcccc);
        let log = EncodeLog {
            address: [0x0a; 20].into(),
            topics: vec![send_event_topic.into()],
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
    fn test_withdrawal_event_hash() {
        let mut execution_outcome = ExecutionOutcome::<reth_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![vec![reth_primitives::Receipt {
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

        let expected_data = vec![
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 153, 153, 153, 153, 153, 153, 153, 153, 153,
            153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
            153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
            153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
            153, 153, 153, 153,
        ];

        let mut hasher = Keccak256::new();
        hasher.update(&expected_data);

        let expected_hash = hasher.finalize();

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_any_withdrawal_events_hash() {
        let mut execution_outcome = ExecutionOutcome::<reth_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![
            vec![
                reth_primitives::Receipt {
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
                reth_primitives::Receipt {
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
            vec![reth_primitives::Receipt {
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

        let expected_data = vec![
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98,
            98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98,
            98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98, 98,
            98, 98, 98, 98, 98, 98, 98, 98, 98, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
            10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
            99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 10, 10, 10, 10,
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11,
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
            11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
            100, 100, 100,
        ];

        let mut hasher = Keccak256::new();
        hasher.update(&expected_data);

        let expected_hash = hasher.finalize();

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_empty_deposit_hash() {
        let mut execution_outcome = ExecutionOutcome::<reth_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![
            vec![reth_primitives::Receipt::default(), reth_primitives::Receipt::default()],
            vec![reth_primitives::Receipt::default(), reth_primitives::Receipt::default()],
        ];

        let actual_hash =
            execution_outcome.calculate_deposit_hash(&bridge_address, &send_event_topic).unwrap();

        assert_eq!(actual_hash, ZERO_BYTES_HASH);
    }

    #[test]
    fn test_empty_withdrawal_root() {
        let mut execution_outcome = ExecutionOutcome::<reth_primitives::Receipt>::default();

        let bridge_address = Address::from([0xa; 20]);
        let send_event_topic = B256::from([0xb; 32]);

        execution_outcome.receipts = vec![
            vec![reth_primitives::Receipt::default(), reth_primitives::Receipt::default()],
            vec![reth_primitives::Receipt::default(), reth_primitives::Receipt::default()],
        ];

        let actual_hash = execution_outcome
            .calculate_withdrawal_root(&bridge_address, &send_event_topic)
            .unwrap();

        assert_eq!(actual_hash, ZERO_BYTES_HASH);
    }
}
