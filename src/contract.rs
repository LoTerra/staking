use crate::msg::{
    ConfigResponse, GetAllBondedResponse, GetBondedResponse, GetHolderResponse, HandleMsg, InitMsg,
    QueryMsg,
};
use crate::state::{
    config, config_read, staking_storage, staking_storage_read, StakingInfo, State,
};
use cosmwasm_std::{
    to_binary, Api, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Env, Extern, HandleResponse,
    HumanAddr, InitResponse, LogAttribute, Order, Querier, StdError, StdResult, Storage, Uint128,
    WasmMsg,
};
use std::ops::{Add, Sub};
use terra_cosmwasm::{TaxCapResponse, TerraQuerier};

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        admin: deps.api.canonical_address(&env.message.sender)?,
        address_cw20_loterra_smart_contract: deps
            .api
            .canonical_address(&msg.address_cw20_loterra_smart_contract)?,
        unbonded_period: msg.unbonded_period,
        denom_reward: msg.denom_reward,
        safe_lock: false,
    };

    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::Stake { amount } => handle_stake(deps, env, amount),
        HandleMsg::UnStake { amount } => handle_unstake(deps, env, amount),
        HandleMsg::ClaimReward {} => handle_claim_reward(deps, env),
        HandleMsg::ClaimUnStaked {} => handle_claim_unstake(deps, env),
        HandleMsg::SafeLock {} => handle_safe_lock(deps, env),
        HandleMsg::Renounce {} => handle_renounce(deps, env),
        HandleMsg::PayoutReward {} => handle_payout_reward(deps, env),
    }
}
fn encode_msg_execute(msg: QueryMsg, address: HumanAddr) -> StdResult<CosmosMsg> {
    Ok(WasmMsg::Execute {
        contract_addr: address,
        msg: to_binary(&msg)?,
        send: vec![],
    }
    .into())
}

pub fn handle_renounce<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    // Load the state
    let mut state = config(&mut deps.storage).load()?;
    let sender = deps.api.canonical_address(&env.message.sender)?;
    if state.admin != sender {
        return Err(StdError::Unauthorized { backtrace: None });
    }
    if state.safe_lock {
        return Err(StdError::generic_err("Contract is locked"));
    }

    state.admin = deps.api.canonical_address(&env.contract.address)?;
    config(&mut deps.storage).save(&state)?;
    Ok(HandleResponse::default())
}

pub fn handle_safe_lock<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    // Load the state
    let mut state = config(&mut deps.storage).load()?;
    let sender = deps.api.canonical_address(&env.message.sender)?;
    if state.admin != sender {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    state.safe_lock = !state.safe_lock;
    config(&mut deps.storage).save(&state)?;

    Ok(HandleResponse::default())
}

pub fn handle_stake<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with stake"));
    }
    if amount.is_zero() {
        return Err(StdError::generic_err("Amount required"));
    }
    // Prepare msg to send
    let msg = QueryMsg::TransferFrom {
        owner: env.message.sender.clone(),
        recipient: env.contract.address.clone(),
        amount,
    };
    // Convert state address of loterra cw-20
    let lottera_human = deps
        .api
        .human_address(&state.address_cw20_loterra_smart_contract)?;
    // Prepare the message
    let res = encode_msg_execute(msg, lottera_human)?;

    let sender_canonical = deps.api.canonical_address(&env.message.sender)?;
    match staking_storage(&mut deps.storage).may_load(&sender_canonical.as_slice())? {
        Some(_e) => {
            staking_storage(&mut deps.storage).update::<_>(
                &sender_canonical.as_slice(),
                |stake| {
                    let mut stake_data = stake.unwrap();
                    stake_data.bonded = stake_data.bonded.add(amount);

                    Ok(stake_data)
                },
            )?;
        }
        None => {
            staking_storage(&mut deps.storage).save(
                &sender_canonical.as_slice(),
                &StakingInfo {
                    bonded: amount,
                    un_bonded: Uint128::zero(),
                    period: 0,
                    available: Uint128::zero(),
                },
            )?;
        }
    };

    Ok(HandleResponse {
        messages: vec![res],
        log: vec![
            LogAttribute {
                key: "action".to_string(),
                value: "bond lota".to_string(),
            },
            LogAttribute {
                key: "from".to_string(),
                value: env.message.sender.to_string(),
            },
            LogAttribute {
                key: "to".to_string(),
                value: env.contract.address.to_string(),
            },
            LogAttribute {
                key: "amount".to_string(),
                value: amount.to_string(),
            },
        ],
        data: None,
    })
}

pub fn handle_unstake<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Uint128,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds with un_stake"));
    }
    if amount.is_zero() {
        return Err(StdError::generic_err("Amount required"));
    }

    let sender_canonical = deps.api.canonical_address(&env.message.sender)?;
    match staking_storage(&mut deps.storage).may_load(&sender_canonical.as_slice())? {
        Some(_e) => {
            staking_storage(&mut deps.storage).update::<_>(
                &sender_canonical.as_slice(),
                |stake| {
                    let mut stake_data = stake.unwrap();
                    if stake_data.bonded < amount {
                        return Err(StdError::generic_err(format!(
                            "You can't unStake more than you have ({})",
                            stake_data.bonded.u128().to_string()
                        )));
                    }
                    stake_data.bonded = stake_data.bonded.sub(amount)?;
                    stake_data.un_bonded = stake_data.un_bonded.add(amount);
                    stake_data.period = env.block.height + state.unbonded_period;
                    Ok(stake_data)
                },
            )?;
        }
        None => {
            return Err(StdError::Unauthorized { backtrace: None });
        }
    };

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            LogAttribute {
                key: "action".to_string(),
                value: "unbond lota".to_string(),
            },
            LogAttribute {
                key: "amount".to_string(),
                value: amount.to_string(),
            },
        ],
        data: None,
    })
}

pub fn handle_claim_unstake<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds"));
    }

    let sender_canonical = deps.api.canonical_address(&env.message.sender)?;
    let store = staking_storage(&mut deps.storage).load(&sender_canonical.as_slice())?;

    if store.period > env.block.height {
        return Err(StdError::generic_err(format!(
            "Your unBonded token will be released at block {}",
            store.period
        )));
    }
    if store.un_bonded.is_zero() {
        return Err(StdError::generic_err("No amount available"));
    }
    // Prepare msg to send
    let msg = QueryMsg::Transfer {
        recipient: env.message.sender.clone(),
        amount: store.un_bonded,
    };
    // Convert state address of loterra cw-20
    let lottera_human = deps
        .api
        .human_address(&state.address_cw20_loterra_smart_contract)?;
    // Prepare the message
    let res = encode_msg_execute(msg, lottera_human)?;

    staking_storage(&mut deps.storage).update::<_>(&sender_canonical.as_slice(), |stake| {
        let mut stake_data = stake.unwrap();
        stake_data.un_bonded = Uint128::zero();
        stake_data.period = 0;
        Ok(stake_data)
    })?;

    Ok(HandleResponse {
        messages: vec![res],
        log: vec![
            LogAttribute {
                key: "action".to_string(),
                value: "claim unstake".to_string(),
            },
            LogAttribute {
                key: "from".to_string(),
                value: env.contract.address.to_string(),
            },
            LogAttribute {
                key: "to".to_string(),
                value: env.message.sender.to_string(),
            },
            LogAttribute {
                key: "amount".to_string(),
                value: store.un_bonded.to_string(),
            },
        ],
        data: None,
    })
}

pub fn handle_claim_reward<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;

    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    if !env.message.sent_funds.is_empty() {
        return Err(StdError::generic_err("Do not send funds"));
    }

    let sender_canonical = deps.api.canonical_address(&env.message.sender)?;
    let store = staking_storage(&mut deps.storage).load(&sender_canonical.as_slice())?;
    let contract_balance = deps
        .querier
        .query_balance(env.contract.address.clone(), &state.denom_reward)?;

    if store.available.is_zero() {
        return Err(StdError::generic_err("No rewards available"));
    }

    if contract_balance.amount < store.available {
        return Err(StdError::generic_err("Contract balance too low"));
    }
    let querier = TerraQuerier::new(&deps.querier);
    let tax_cap: TaxCapResponse = querier.query_tax_cap(&state.denom_reward)?;
    let amount_to_send = store.available.sub(tax_cap.cap)?;

    let msg = BankMsg::Send {
        from_address: env.contract.address.clone(),
        to_address: env.message.sender.clone(),
        amount: vec![Coin {
            denom: state.denom_reward,
            amount: amount_to_send,
        }],
    };

    staking_storage(&mut deps.storage).update::<_>(&sender_canonical.as_slice(), |stake| {
        let mut stake_data = stake.unwrap();
        stake_data.available = Uint128::zero();
        Ok(stake_data)
    })?;

    Ok(HandleResponse {
        messages: vec![msg.into()],
        log: vec![
            LogAttribute {
                key: "action".to_string(),
                value: "claim reward".to_string(),
            },
            LogAttribute {
                key: "from".to_string(),
                value: env.contract.address.to_string(),
            },
            LogAttribute {
                key: "to".to_string(),
                value: env.message.sender.to_string(),
            },
            LogAttribute {
                key: "amount".to_string(),
                value: store.available.to_string(),
            },
        ],
        data: None,
    })
}

pub fn handle_payout_reward<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let state = config(&mut deps.storage).load()?;
    if state.safe_lock {
        return Err(StdError::generic_err(
            "Contract deactivated for update or/and preventing security issue",
        ));
    }

    let sent = match env.message.sent_funds.len() {
        0 => Err(StdError::generic_err(
            "You need to send funds for share holders"
        )),
        1 => {
            if env.message.sent_funds[0].denom == state.denom_reward {
                Ok(env.message.sent_funds[0].amount)
            } else {
                Err(StdError::generic_err(format!(
                    "Only {} is accepted",
                    state.denom_reward
                )))
            }
        }
        _ => Err(StdError::generic_err(format!(
            "Send only {}, extra denom detected",
            state.denom_reward
        ))),
    }?;

    let mut total_staked = Uint128::zero();
    let staking = staking_storage(&mut deps.storage)
        .range(None, None, Order::Descending)
        .flat_map(|item| {
            item.and_then(|(k, stake)| {
                if !stake.bonded.is_zero() {
                    total_staked = total_staked.add(stake.bonded);
                }

                Ok(GetBondedResponse {
                    address: CanonicalAddr::from(k),
                    bonded: stake.bonded,
                })
            })
        })
        .collect::<Vec<GetBondedResponse>>();

    if total_staked.is_zero() {
        //return Err(StdError::generic_err("No amount staked"));
        let msg_no_stakers = BankMsg::Send {
            from_address: env.contract.address.clone(),
            to_address: env.message.sender,
            amount: vec![Coin {
                denom: state.denom_reward,
                amount: sent,
            }],
        };

        return Ok(HandleResponse {
            messages: vec![msg_no_stakers.into()],
            log: vec![],
            data: None,
        });
    }

    let mut claimed_amount = Uint128::zero();
    for stake_holder in staking {
        if !stake_holder.bonded.is_zero() {
            let reward = stake_holder.bonded.multiply_ratio(sent, total_staked);
            if !reward.is_zero() {
                claimed_amount = claimed_amount.add(reward);
                staking_storage(&mut deps.storage).update::<_>(
                    &stake_holder.address.as_slice(),
                    |stake| {
                        let mut stake_data = stake.unwrap();
                        stake_data.available = stake_data.available.add(reward);
                        Ok(stake_data)
                    },
                )?;
            }
        }
    }

    let final_refund_balance = sent.sub(claimed_amount)?;
    if final_refund_balance.is_zero() {
        return Ok(HandleResponse::default());
    }

    let msg = BankMsg::Send {
        from_address: env.contract.address.clone(),
        to_address: env.message.sender,
        amount: vec![Coin {
            denom: state.denom_reward,
            amount: final_refund_balance,
        }],
    };

    Ok(HandleResponse {
        messages: vec![msg.into()],
        log: vec![],
        data: None,
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::GetHolder { address } => to_binary(&query_holder(deps, address)?),
        QueryMsg::TransferFrom { .. } => to_binary(&query_transfer_from(deps)?),
        QueryMsg::Transfer { .. } => to_binary(&query_transfer(deps)?),
        QueryMsg::GetAllBonded {} => to_binary(&query_all_bonded(deps)?),
    }
}

fn query_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ConfigResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(state)
}

fn query_holder<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: HumanAddr,
) -> StdResult<GetHolderResponse> {
    let address_to_canonical = deps.api.canonical_address(&address)?;
    let store =
        match staking_storage_read(&deps.storage).may_load(&address_to_canonical.as_slice())? {
            Some(stake) => Some(stake),
            None => {
                return Err(StdError::NotFound {
                    kind: "not found".to_string(),
                    backtrace: None,
                })
            }
        }
        .unwrap();

    Ok(GetHolderResponse {
        address,
        bonded: store.bonded,
        un_bonded: store.un_bonded,
        available: store.available,
        period: store.period,
    })
}
fn query_all_bonded<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<GetAllBondedResponse> {
    let total_bonded = staking_storage_read(&deps.storage)
        .range(None, None, Order::Descending)
        .flat_map(|item| item.and_then(|(_k, stake)| Ok(stake.bonded)))
        .collect::<Vec<Uint128>>();

    let mut total = Uint128::zero();
    for bonded in total_bonded {
        total = total.add(bonded);
    }
    Ok(GetAllBondedResponse {
        total_bonded: total,
    })
}

fn query_transfer_from<S: Storage, A: Api, Q: Querier>(
    _deps: &Extern<S, A, Q>,
) -> StdResult<StdError> {
    Err(StdError::Unauthorized { backtrace: None })
}
fn query_transfer<S: Storage, A: Api, Q: Querier>(_deps: &Extern<S, A, Q>) -> StdResult<StdError> {
    Err(StdError::Unauthorized { backtrace: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_querier::mock_dependencies_custom;
    use cosmwasm_std::coins;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::StdError::GenericErr;

    struct BeforeAll {
        default_length: usize,
        default_sender: HumanAddr,
        default_sender_two: HumanAddr,
        default_sender_owner: HumanAddr,
        default_contract_address: HumanAddr,
        default_contract_address_two: HumanAddr,
    }
    fn before_all() -> BeforeAll {
        BeforeAll {
            default_length: HumanAddr::from("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k").len(),
            default_sender: HumanAddr::from("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007"),
            default_sender_two: HumanAddr::from("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q008"),
            default_sender_owner: HumanAddr::from("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k"),
            default_contract_address: HumanAddr::from(
                "terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20LOTA",
            ),
            default_contract_address_two: HumanAddr::from(
                "terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5LOTERRA",
            ),
        }
    }

    fn default_init<S: Storage, A: Api, Q: Querier>(mut deps: &mut Extern<S, A, Q>) {
        let before_all = before_all();
        let init_msg = InitMsg {
            address_cw20_loterra_smart_contract: before_all.default_contract_address,
            unbonded_period: 100,
            denom_reward: "uusd".to_string(),
        };
        let res = init(
            &mut deps,
            mock_env("terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k", &[]),
            init_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn proper_initialization() {
        let before_all = before_all();
        let mut deps = mock_dependencies(before_all.default_length, &[]);
        let env = mock_env("creator", &coins(1000, "earth"));
        default_init(&mut deps);
    }
    mod safe_lock {
        use super::*;
        // handle_switch

        #[test]
        fn only_admin() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_two, &[]);

            let res = handle_safe_lock(&mut deps, env);
            match res {
                Err(StdError::Unauthorized { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_owner, &[]);

            // Switch to Off
            let res = handle_safe_lock(&mut deps, env.clone()).unwrap();
            assert_eq!(res.messages.len(), 0);
            let state = config(&mut deps.storage).load().unwrap();
            assert!(state.safe_lock);
            // Switch to On
            let res = handle_safe_lock(&mut deps, env).unwrap();
            println!("{:?}", res);
            let state = config(&mut deps.storage).load().unwrap();
            assert!(!state.safe_lock);
        }
    }
    mod renounce {
        use super::*;
        // handle_renounce
        #[test]
        fn only_admin() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_two, &[]);

            let res = handle_renounce(&mut deps, env);
            match res {
                Err(StdError::Unauthorized { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn safe_lock_on() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_owner, &[]);

            let mut state = config(&mut deps.storage).load().unwrap();
            state.safe_lock = true;
            config(&mut deps.storage).save(&state).unwrap();

            let res = handle_renounce(&mut deps, env);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Contract is locked");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_owner.clone(), &[]);

            // Transfer power to admin
            let res = handle_renounce(&mut deps, env.clone()).unwrap();
            assert_eq!(res.messages.len(), 0);
            let state = config(&mut deps.storage).load().unwrap();
            assert_ne!(
                state.admin,
                deps.api
                    .canonical_address(&before_all.default_sender_owner)
                    .unwrap()
            );
            assert_eq!(
                state.admin,
                deps.api.canonical_address(&env.contract.address).unwrap()
            );
        }
    }

    mod stake {
        use super::*;
        // handle_stake
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender_owner.clone(),
                &[Coin {
                    denom: "x".to_string(),
                    amount: Uint128(2_000),
                }],
            );
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Do not send funds with stake");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn amount_required() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_owner.clone(), &[]);
            let msg = HandleMsg::Stake { amount: Uint128(0) };
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Amount required");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender_owner.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: before_all.default_contract_address,
                    msg: Binary::from(r#"{"transfer_from":{"owner":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20qu3k","recipient":"cosmos2contract","amount":"2000"}}"#.as_bytes()),
                    send: vec![]
                })
            );
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_owner)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(2_000));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128::zero());
            assert_eq!(store.period, 0);

            // Stake more
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_owner)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(4_000));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128::zero());
            assert_eq!(store.period, 0);

            let all_bonded = query_all_bonded(&deps).unwrap();
            assert_eq!(all_bonded.total_bonded, Uint128(4_000));
        }
    }
    mod unstake {
        use super::*;
        // handle_unstake
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[Coin {
                    denom: "x".to_string(),
                    amount: Uint128(2_000),
                }],
            );
            let msg = HandleMsg::UnStake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Do not send funds with un_stake");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_stake_registered_from_this_address() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            let msg = HandleMsg::UnStake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(StdError::Unauthorized { .. }) => {}
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn unstake_more_than_staked() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // UnStake some funds
            let msg = HandleMsg::UnStake {
                amount: Uint128(3_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "You can\'t unStake more than you have (2000)");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn amount_required() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            let msg = HandleMsg::UnStake { amount: Uint128(0) };
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Amount required");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // UnStake some funds
            let msg = HandleMsg::UnStake {
                amount: Uint128(1_500),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            assert_eq!(res.messages.len(), 0);
            let state = config(&mut deps.storage).load().unwrap();
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(500));
            assert_eq!(store.un_bonded, Uint128(1_500));
            assert_eq!(store.available, Uint128::zero());
            assert_eq!(store.period, env.block.height + state.unbonded_period);

            let all_bonded = query_all_bonded(&deps).unwrap();
            assert_eq!(all_bonded.total_bonded, Uint128(500));
        }
    }
    mod claim_unstake {
        use super::*;
        // handle_claim_unstake
        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[Coin {
                    denom: "x".to_string(),
                    amount: Uint128(2_000),
                }],
            );
            let msg = HandleMsg::ClaimUnStaked {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Do not send funds");
                }
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn unbonded_period_not_ended() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // UnStake some funds
            let msg = HandleMsg::UnStake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Claim unStaked funds
            let msg = HandleMsg::ClaimUnStaked {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Your unBonded token will be released at block 12445");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_amount_to_unstake() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Claim unStaked funds
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            let mut env = mock_env(before_all.default_sender.clone(), &[]);
            env.block.height = store.period + 1;
            let msg = HandleMsg::ClaimUnStaked {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "No amount available");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // UnStake some funds
            let msg = HandleMsg::UnStake {
                amount: Uint128(1_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Claim unStaked funds
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            let mut env = mock_env(before_all.default_sender.clone(), &[]);
            env.block.height = store.period + 1;
            let msg = HandleMsg::ClaimUnStaked {};
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: before_all.default_contract_address,
                    msg: Binary::from(
                        r#"{"transfer":{"recipient":"terra1q88h7ewu6h3am4mxxeqhu3srt7zw4z5s20q007","amount":"1000"}}"#
                            .as_bytes()
                    ),
                    send: vec![]
                })
            );
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(1_000));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128::zero());
            assert_eq!(store.period, 0);
        }
    }
    mod claim_reward {
        use super::*;
        // handle_claim_reward

        #[test]
        fn do_not_send_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[Coin {
                    denom: "x".to_string(),
                    amount: Uint128(2_000),
                }],
            );
            let msg = HandleMsg::ClaimReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Do not send funds");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn no_rewards_available() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();

            let msg = HandleMsg::ClaimReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "No rewards available");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn contract_balance_to_low() {
            let before_all = before_all();
            let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            let store = staking_storage(&mut deps.storage)
                .update::<_>(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender.clone())
                        .unwrap()
                        .as_slice(),
                    |stake| {
                        let mut stake_data = stake.unwrap();
                        stake_data.available = Uint128(11_000);
                        Ok(stake_data)
                    },
                )
                .unwrap();

            let msg = HandleMsg::ClaimReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Contract balance too low");
                }
                _ => panic!("Unexpected error"),
            }
        }
        #[test]
        fn success() {
            let before_all = before_all();

            let mut deps = mock_dependencies_custom(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            /*let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );*/
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            // Stake some funds
            let msg = HandleMsg::Stake {
                amount: Uint128(2_000),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            let store = staking_storage(&mut deps.storage)
                .update::<_>(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender.clone())
                        .unwrap()
                        .as_slice(),
                    |stake| {
                        let mut stake_data = stake.unwrap();
                        stake_data.available = Uint128(1_000);
                        Ok(stake_data)
                    },
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(2_000));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(1_000));
            assert_eq!(store.period, 0);
            let msg = HandleMsg::ClaimReward {};
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    from_address: HumanAddr::from("cosmos2contract"),
                    to_address: before_all.default_sender.clone(),
                    amount: vec![Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128(999)
                    }]
                })
            );
            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            assert_eq!(store.bonded, Uint128(2_000));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128::zero());
            assert_eq!(store.period, 0);
        }
    }
    mod payout_reward {
        use super::*;
        // handle_payout_reward
        #[test]
        fn send_some_funds() {
            let before_all = before_all();
            let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            default_init(&mut deps);
            let env = mock_env(before_all.default_sender.clone(), &[]);
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "You need to send funds for share holders");
                }
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn sent_wrong_denom() {
            let before_all = before_all();
            let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[Coin {
                    denom: "wrong".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Only uusd is accepted");
                }
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn sent_extra_denom() {
            let before_all = before_all();
            let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[
                    Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128(10_000),
                    },
                    Coin {
                        denom: "wrong".to_string(),
                        amount: Uint128(10_000),
                    },
                ],
            );
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone());
            println!("{:?}", res);
            match res {
                Err(GenericErr {
                    msg,
                    backtrace: None,
                }) => {
                    assert_eq!(msg, "Send only uusd, extra denom detected");
                }
                _ => panic!("Unexpected error"),
            }
        }

        #[test]
        fn no_amount_staked() {
            let before_all = before_all();
            let mut deps = mock_dependencies(
                before_all.default_length,
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            default_init(&mut deps);
            let env = mock_env(
                before_all.default_sender.clone(),
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: Uint128(10_000),
                }],
            );
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    from_address: env.contract.address,
                    to_address: before_all.default_sender,
                    amount: vec![Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128(10000)
                    }]
                })
            );
            println!("{:?}", res);
        }

        #[test]
        fn success_more_rewards_than_total_staked() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            // Stake some funds
            let env = mock_env(before_all.default_sender.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(2_153),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Stake more funds
            let env = mock_env(before_all.default_sender_two.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(15_345),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Stake more funds
            let env = mock_env(before_all.default_sender_owner.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(22_178),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            let total_rewards = Uint128(124_368);
            let env = mock_env(
                before_all.default_contract_address.clone(),
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: total_rewards.clone(),
                }],
            );
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    from_address: HumanAddr::from("cosmos2contract"),
                    to_address: before_all.default_contract_address.clone(),
                    amount: vec![Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128(2)
                    }]
                })
            );

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards1 = store.available;
            assert_eq!(store.bonded, Uint128(2_153));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(6_748));
            assert_eq!(store.period, 0);

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_two)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards2 = store.available;
            assert_eq!(store.bonded, Uint128(15_345));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(48_100));
            assert_eq!(store.period, 0);

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_owner)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards3 = store.available;
            assert_eq!(store.bonded, Uint128(22_178));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(69_518));
            assert_eq!(store.period, 0);

            // Assert total shared rewards is equal sub refunds of 1 UST
            let total_shared_rewards = rewards1.u128() + rewards2.u128() + rewards3.u128();
            assert_eq!(total_rewards.u128() - 2, total_shared_rewards)
        }
        #[test]
        fn success_less_rewards_than_total_staked() {
            let before_all = before_all();
            let mut deps = mock_dependencies(before_all.default_length, &[]);
            default_init(&mut deps);
            // Stake some funds
            let env = mock_env(before_all.default_sender.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(2_153),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Stake more funds
            let env = mock_env(before_all.default_sender_two.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(15_345),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            // Stake more funds
            let env = mock_env(before_all.default_sender_owner.clone(), &[]);
            let msg = HandleMsg::Stake {
                amount: Uint128(22_178),
            };
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            let total_rewards = Uint128(12_368);
            let env = mock_env(
                before_all.default_contract_address.clone(),
                &[Coin {
                    denom: "uusd".to_string(),
                    amount: total_rewards.clone(),
                }],
            );
            let msg = HandleMsg::PayoutReward {};
            let res = handle(&mut deps, env.clone(), msg.clone()).unwrap();
            println!("{:?}", res);
            assert_eq!(res.messages.len(), 1);
            assert_eq!(
                res.messages[0],
                CosmosMsg::Bank(BankMsg::Send {
                    from_address: HumanAddr::from("cosmos2contract"),
                    to_address: before_all.default_contract_address.clone(),
                    amount: vec![Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128(1)
                    }]
                })
            );

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards1 = store.available;
            assert_eq!(store.bonded, Uint128(2_153));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(671));
            assert_eq!(store.period, 0);

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_two)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards2 = store.available;
            assert_eq!(store.bonded, Uint128(15_345));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(4_783));
            assert_eq!(store.period, 0);

            let store = staking_storage(&mut deps.storage)
                .load(
                    &deps
                        .api
                        .canonical_address(&before_all.default_sender_owner)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            println!("{:?}", store);
            let rewards3 = store.available;
            assert_eq!(store.bonded, Uint128(22_178));
            assert_eq!(store.un_bonded, Uint128::zero());
            assert_eq!(store.available, Uint128(6_913));
            assert_eq!(store.period, 0);

            // Assert total shared rewards is equal sub refunds of 1 UST
            let total_shared_rewards = rewards1.u128() + rewards2.u128() + rewards3.u128();
            assert_eq!(total_rewards.u128() - 1, total_shared_rewards)
        }
    }
}
