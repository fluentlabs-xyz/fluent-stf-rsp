use alloy_consensus::TxReceipt;
use alloy_primitives::{Address, Keccak256, B256};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolType, SolValue};
use bincode::Error;
use reth_execution_types::ExecutionOutcome;

sol! {
    struct Log{
        address address;
        uint256[] topics;
        bytes data;
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

pub trait CalculateWithdrawalEventHash {
    fn calculate_withdrawal_event_hash(
        &self,
        bridge_address: Address,
        send_topic: B256,
    ) -> Result<B256, Error>;
}

impl<T: TxReceipt<Log = alloy_primitives::Log>> CalculateWithdrawalEventHash
    for ExecutionOutcome<T>
{
    fn calculate_withdrawal_event_hash(
        &self,
        bridge_address: Address,
        send_topic: B256,
    ) -> Result<B256, Error> {
        let withdrawal_logs = self
            .receipts
            .iter()
            .flat_map(|receipt| receipt.iter().filter(TxReceipt::status).flat_map(TxReceipt::logs))
            .filter(|log| {
                log.address == bridge_address
                    && log.data.topics().get(0).map(|topic| *topic == send_topic).unwrap_or(false)
            })
            .map(|log| Log::from(log).abi_encode_packed())
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        println!("Log: {:?}", withdrawal_logs);
        let mut hasher = Keccak256::new();
        hasher.update(&withdrawal_logs);

        Ok(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxType;
    use alloy_primitives::U256;
    use alloy_primitives::{Address, Bytes, Keccak256, Log, LogData, B256};
    use alloy_sol_types::SolValue;
    use reth_execution_types::ExecutionOutcome;

    use crate::withdrawal_event_hash::{CalculateWithdrawalEventHash, Log as EncodeLog};

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

        execution_outcome.receipts = vec![
            vec![reth_primitives::Receipt::default(), reth_primitives::Receipt::default()],
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
                            data: LogData::new(vec![send_event_topic], Bytes::from([0x99; 64]))
                                .unwrap(),
                        },
                    ],
                },
                reth_primitives::Receipt::default(),
            ],
            vec![
                reth_primitives::Receipt::default(),
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
                                vec![B256::from([0xc; 32])],
                                Bytes::from([0x99; 64]),
                            )
                            .unwrap(),
                        },
                    ],
                },
                reth_primitives::Receipt::default(),
            ],
        ];

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

        let actual_hash = execution_outcome
            .calculate_withdrawal_event_hash(bridge_address, send_event_topic)
            .unwrap();

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

        let actual_hash = execution_outcome
            .calculate_withdrawal_event_hash(bridge_address, send_event_topic)
            .unwrap();

        assert_eq!(actual_hash, expected_hash);
    }
}
