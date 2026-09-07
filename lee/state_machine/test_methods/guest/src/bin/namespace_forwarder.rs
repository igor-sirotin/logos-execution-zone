use lee_core::{
    account::{AccountId, BalanceDiff, Data, Input, Position},
    program::{
        ChainedCall, InstructionData, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff,
        read_lee_call, respond_unsupported_call,
    },
};

// `(own write, chained calls)`.
//
// The write names an account of the caller's choosing and lands under this program's own
// namespace, which is the only shard rule 3 lets it touch. When that account is one nothing
// handed it, the position enters the transaction through the output diff alone — the case a
// caller tracking its own fetches cannot see.
//
// Each chained call carries its position explicitly, so a callee can be pointed at a position
// this program manufactured rather than at one it was given.
type Instruction = (
    Option<(AccountId, Vec<u8>)>,
    Vec<(AccountId, Position, InstructionData)>,
);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (own_write, callees),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([own]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut state_diffs = vec![ShardStateDiff::unchanged(own)];
    if let Some((target, data)) = own_write {
        // A fresh public account: balance 0, this program's shard still empty. The circuit
        // anchors a first sight to exactly these values and the verifier re-derives them from
        // chain, so anything else would be rejected rather than trusted.
        state_diffs.push(ShardStateDiff::new(
            Input::named(target, false, 0, self_account_id, Data::empty()),
            BalanceDiff::Add(0),
            data.try_into()
                .expect("provided data should fit into data limit"),
        ));
    }

    let chained_calls = callees
        .into_iter()
        .map(|(callee, position, callee_instruction)| ChainedCall {
            program_account_id: callee,
            instruction_data: callee_instruction,
            positions: vec![position],
            pda_seeds: vec![],
        })
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
