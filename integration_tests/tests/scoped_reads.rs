#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{borrow::Cow, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention, public_mention,
    utils::{account_balance, get_account, get_account_view, new_account, send},
};
use lee::{
    AccountId, Position, PrivateKey, PublicKey,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::{account::Nonce, program::PROGRAM_LOADER_ACCOUNT_ID};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;
use wallet::{AccountIdentity, program_facades::program_loader::ProgramLoader};

// `DATA_MAX_LENGTH`, and therefore 716_800 storage-gas units against a `MAX_GAS_STOR` of
// 1_000_000 — one such write fills a block and no two can share one.
const BLOAT_SHARD_BYTES: usize = 700 * 1024;

// Four of these serialize to roughly 11.5 MB as JSON-RPC decimal arrays (up to four characters
// a byte), past jsonrpsee's 10 MiB `max_response_body_size`.
const BLOAT_WRITERS: usize = 4;

// jsonrpsee refuses to serialize a response past `max_response_body_size` and answers with its
// own error object instead; anything else means the read failed for an unrelated reason.
fn is_oversized_response(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<sequencer_service_rpc::ClientError>(),
        Some(sequencer_service_rpc::ClientError::Call(object))
            if object.code() == jsonrpsee::types::error::OVERSIZED_RESPONSE_CODE
    )
}

// Deterministic key for an account this test claims for the first time.
fn fresh_key(seed: u8) -> (PrivateKey, AccountId) {
    let key = PrivateKey::try_new([seed; 32]).expect("seed is a valid private key");
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    (key, account_id)
}

// Submits one public transaction and waits for it to land.
async fn submit(
    ctx: &TestContext,
    program: AccountId,
    positions: Vec<Position>,
    nonces: Vec<Nonce>,
    instruction: impl borsh::BorshSerialize,
    payer: &PublicAccountPrivateInitialData,
    extra_signers: &[&PrivateKey],
) -> Result<()> {
    let message = lee::public_transaction::Message::try_new_with_fees(
        program,
        positions,
        nonces,
        instruction,
        common::test_utils::test_fee_declaration(payer.account_id),
    )?;
    let mut keys = extra_signers.to_vec();
    keys.push(&payer.pub_sign_key);
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &keys);

    ctx.sequencer_client()
        .send_transaction(LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        )))
        .await?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    Ok(())
}

// Wallet-owned segment accounts, as many as `byte_len` needs — `deploy` requires the count to
// match its own chunking exactly.
async fn fresh_segments(ctx: &mut TestContext, byte_len: usize) -> Result<Vec<AccountId>> {
    let mut segments = Vec::new();
    for _ in 0..byte_len.div_ceil(MAX_SEGMENT_DATA_LEN) {
        segments.push(new_account(ctx, false, None).await?);
    }
    Ok(segments)
}

// Uploads `program` and claims a header at its own bijection address, so the sequencer can
// resolve the image claim the circuit journals for it. The header is not an account this wallet
// holds a key for, which is fine: a never-claimed header carries no signature of its own and
// `payer` covers the fees.
async fn deploy_at_bijection(
    ctx: &mut TestContext,
    payer: AccountId,
    program: &Program,
) -> Result<AccountId> {
    let segments = fresh_segments(ctx, program.elf().len()).await?;

    ProgramLoader(ctx.wallet())
        .deploy(
            program.id().into(),
            &segments,
            program.elf().to_vec(),
            true,
            Some(payer),
        )
        .await
}

// Fills `victim` with [`BLOAT_WRITERS`] maximum-size shards owned by programs it has never
// heard of, and returns their addresses.
//
// The attack the plan measures, in miniature: `data_writer` writes the caller's bytes as its own
// shard at whatever account the call names, and rule 3 lets any program do that at any account
// with no authorization at all. `CreateHeader` re-points a fresh address at an existing segment
// chain, so one ELF upload yields as many distinct program addresses as we care to claim — the
// attacker pays for the bytes once and the victim's whole-account read is over the limit
// forever.
async fn bloat_account(ctx: &mut TestContext, victim: AccountId) -> Result<[AccountId; 4]> {
    let payer = &initial_pub_accounts_private_keys()[0];
    let writer = test_programs::data_writer();

    // One upload, then three more headers pointed at the same chain.
    let segments = fresh_segments(ctx, writer.elf().len()).await?;
    let first_header = new_account(ctx, false, None).await?;
    ProgramLoader(ctx.wallet())
        .deploy(
            first_header,
            &segments,
            writer.elf().to_vec(),
            true,
            Some(payer.account_id),
        )
        .await?;

    let mut writers = vec![first_header];
    while writers.len() < BLOAT_WRITERS {
        let header = new_account(ctx, false, None).await?;
        ProgramLoader(ctx.wallet())
            .create_header(header, segments[0], &segments, true, Some(payer.account_id))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        writers.push(header);
    }

    // One write per block: `MAX_GAS_STOR` is 1_000_000 and storage gas is one unit a byte, so a
    // second 700 KiB write cannot fit alongside the first. The victim never signs any of these —
    // rule 3 lets a program write its own shard anywhere, which is the whole attack.
    for writer_id in &writers {
        let payer_nonce = get_account(ctx, payer.account_id).await?.nonce;
        submit(
            ctx,
            *writer_id,
            vec![Position::new(victim, *writer_id)],
            vec![payer_nonce],
            vec![0xFF_u8; BLOAT_SHARD_BYTES],
            payer,
            &[],
        )
        .await?;
    }

    writers
        .try_into()
        .map_err(|_ignored| anyhow::anyhow!("writer count is BLOAT_WRITERS by construction"))
}

// The premise the rest of this file rests on: once four strangers have filled `victim`, the
// whole-account read is over jsonrpsee's response limit while the scoped read is not.
//
// If this ever stops failing, the DoS the scoped reads defend against has gone away and every
// other test here is measuring nothing — so it also carries the fixture's own invariants, rather
// than paying for a second nine-transaction build to assert them.
#[test]
async fn a_bloated_account_defeats_the_whole_account_read_but_not_the_scoped_one() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];

    let writers = bloat_account(&mut ctx, victim).await?;

    let error = get_account(&ctx, victim)
        .await
        .expect_err("the whole-account read must fail once the account is bloated");
    assert!(
        is_oversized_response(&error),
        "the read must fail on response size specifically, not on any error: {error:?}"
    );

    // Distinct addresses off one upload — the reason the attack is cheap — each holding a full
    // shard, and each reachable through a scoped read that the whole-account read cannot serve.
    for (index, writer) in writers.iter().enumerate() {
        assert!(
            !writers[..index].contains(writer),
            "every bloat writer must be a distinct address"
        );
        let (_, view) = get_account_view(&ctx, victim, Some(*writer)).await?;
        assert_eq!(view.shards.len(), 1, "a scoped read carries one shard");
        assert_eq!(view.shards[writer].as_ref().len(), BLOAT_SHARD_BYTES);
    }

    // Balance-only is the narrowest read of all and touches none of the attacker's bytes.
    let (_, balance_only) = get_account_view(&ctx, victim, None).await?;
    assert!(balance_only.shards.is_empty());

    Ok(())
}

// T1 — a public transfer both out of and into a bloated account still builds and lands.
#[test]
async fn public_transfer_survives_a_bloated_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let accounts = ctx.existing_public_accounts();
    let victim = accounts[0];
    let counterparty = accounts[1];

    bloat_account(&mut ctx, victim).await?;

    let counterparty_before = account_balance(&ctx, counterparty).await?;

    send(
        &mut ctx,
        public_mention(victim),
        public_mention(counterparty),
        100,
    )
    .await?;

    assert_eq!(
        account_balance(&ctx, counterparty).await?,
        counterparty_before + 100
    );

    // Read again immediately before the return transfer: the outgoing one already moved the
    // victim's balance, so comparing against `victim_before` would pass even if this reverted.
    let victim_before_return = account_balance(&ctx, victim).await?;

    send(
        &mut ctx,
        public_mention(counterparty),
        public_mention(victim),
        100,
    )
    .await?;

    assert_eq!(
        account_balance(&ctx, victim).await?,
        victim_before_return + 100,
        "the return transfer must have credited the victim, not merely been included"
    );

    Ok(())
}

// T2 — a privacy-preserving transaction naming a bloated account as a public mention (a
// deshield into it) prepares, proves and lands.
//
// The prover is the wallet here, so this is the path where a sparse fetch could have changed an
// outcome rather than merely a response size.
// Current-thread, matching every other private-transaction test in this suite. The resolver
// bridges back to the runtime with `Handle::block_on` from a `spawn_blocking` thread, which under
// this flavor works only because the test's own `block_on` drives IO while awaiting the join
// handle — if this ever hangs, that is the thing to look at, and `flavor = "multi_thread"` the fix.
#[test]
async fn private_deshield_into_a_bloated_account_survives() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let victim = ctx.existing_public_accounts()[0];
    let sender = ctx.existing_private_accounts()[0];

    bloat_account(&mut ctx, victim).await?;

    let victim_before = account_balance(&ctx, victim).await?;

    send(
        &mut ctx,
        private_mention(sender),
        public_mention(victim),
        100,
    )
    .await?;

    assert_eq!(account_balance(&ctx, victim).await?, victim_before + 100);

    Ok(())
}

// T3 — both of `program_loader`'s account reads, over a bloated segment account.
//
// `deploy` and `update` never reach `resolve_chain`; the CLI and the FFI do, so the test calls it
// the way they do. `write_segment`'s `next_segment` check is the other read.
#[test]
async fn loader_reads_survive_a_bloated_segment_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = &initial_pub_accounts_private_keys()[0];

    // A real segment, then a stranger's shard piled on top of it. Its loader record is untouched:
    // the shards are namespaced, so the chain still resolves — provided the read is scoped.
    let (segment_key, segment_id) = fresh_key(0xD0);
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
    submit(
        &ctx,
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![Position::new(segment_id, PROGRAM_LOADER_ACCOUNT_ID)],
        vec![Nonce(0), payer_nonce],
        program_loader_core::Instruction::WriteSegment {
            bytecode: test_programs::data_writer().elf().to_vec(),
            next_segment: None,
        },
        payer,
        &[&segment_key],
    )
    .await?;

    bloat_account(&mut ctx, segment_id).await?;

    assert!(
        get_account(&ctx, segment_id).await.is_err(),
        "the segment account must be past the whole-account response limit"
    );

    let loader = ProgramLoader(ctx.wallet());

    let chain = loader.resolve_chain(segment_id).await?;
    assert_eq!(chain, vec![segment_id]);

    // The other read: `write_segment` checks that the `next_segment` it is asked to link to
    // really holds a segment record, and that account is the bloated one.
    let (_, head_id) = fresh_key(0xD1);
    loader
        .write_segment(
            head_id,
            test_programs::data_writer().elf().to_vec(),
            Some(segment_id),
            Some(payer.account_id),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let chain_from_head = loader.resolve_chain(head_id).await?;
    assert_eq!(chain_from_head, vec![head_id, segment_id]);

    Ok(())
}

// T4 — a chained call opening a namespace the top-level mention never named.
//
// `namespace_forwarder` reads `(X, P)` and chains into `data_writer` naming `(X, Q)`. The wallet
// fetches only `(X, P)`, so `(X, Q)` — which the chain really does hold, because the test writes
// it first — reaches the prover through the resolver or not at all. Without it the circuit
// journals an empty pre-state at `(X, Q)` and the sequencer rejects the proof.
// Same current-thread caveat as `private_deshield_into_a_bloated_account_survives`.
#[test]
async fn a_chained_call_resolves_a_namespace_the_mention_never_named() -> Result<()> {
    let mut ctx = TestContext::new().await?;
    let payer = &initial_pub_accounts_private_keys()[0];
    let account_id = ctx.existing_public_accounts()[0];

    // Both programs must really be on chain: the circuit journals a `ProgramImageClaim` for
    // every program it invoked, and the sequencer checks each against chain state.
    let q = test_programs::data_writer();
    let p = Program::new_unchecked(
        test_methods::NAMESPACE_FORWARDER_ID,
        Cow::Borrowed(test_methods::NAMESPACE_FORWARDER_ELF),
    );
    let q_id = deploy_at_bijection(&mut ctx, payer.account_id, &q).await?;
    let p_id = deploy_at_bijection(&mut ctx, payer.account_id, &p).await?;

    // Populate `(X, Q)` by calling Q directly, so the namespace the chained call opens is one the
    // chain genuinely holds a record at rather than an empty one.
    let existing = vec![0xAB_u8; 32];
    let payer_nonce = get_account(&ctx, payer.account_id).await?.nonce;
    submit(
        &ctx,
        q_id,
        vec![Position::new(account_id, q_id)],
        vec![payer_nonce],
        existing.clone(),
        payer,
        &[],
    )
    .await?;

    let (_, before) = get_account_view(&ctx, account_id, Some(q_id)).await?;
    assert_eq!(before.shards[&q_id].as_ref(), existing.as_slice());

    let rewritten = vec![0xCD_u8; 48];
    let program = ProgramWithDependencies::new(p, p_id, [(q_id, q)].into());

    // The generic private API, mentioning `(X, P)` and nothing else — the shape the FFI and the
    // CLI both reach, and the one that could not be built at all without the resolver.
    ctx.wallet()
        .send_privacy_preserving_tx(
            vec![AccountIdentity::Public(account_id).in_namespace(p_id)],
            Program::serialize_instruction((
                q_id,
                Program::serialize_instruction(rewritten.clone())?,
            ))?,
            &program,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let (_, after) = get_account_view(&ctx, account_id, Some(q_id)).await?;
    assert_eq!(
        after.shards[&q_id].as_ref(),
        rewritten.as_slice(),
        "the chained call must have rewritten the namespace it opened"
    );

    Ok(())
}
