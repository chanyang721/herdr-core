//! Transaction tests with disposable native state and an external policy fixture.
use super::tests::{remove_root, test_core};
use super::*;
use serde_json::json;

fn close_fixture(mode: &str) -> (Arc<Core>, PathBuf, Vec<u32>) {
    let (mut core, root) = test_core();
    let mut argv = if std::process::Command::new("py").args(["-3.12", "-V"]).output().is_ok_and(|o| o.status.success())
    {
        vec!["py".into(), "-3.12".into()]
    } else {
        vec!["python3".into()]
    };
    argv.extend([
        format!("{}/tests/fixtures/close_authorizer.py", env!("CARGO_MANIFEST_DIR")),
        mode.into(),
        root.to_string_lossy().into_owned(),
    ]);
    Arc::get_mut(&mut core).unwrap().close_guard = Some(argv);
    let ids = {
        let mut st = core.lock();
        (0..2)
            .map(|_| {
                let id = st
                    .reg
                    .create(
                        crate::terminals::NewTerminal { argv: vec!["fixture".into()], ..Default::default() },
                        now_ms(),
                    )
                    .unwrap();
                let t = st.reg.terminals.get_mut(&id).unwrap();
                t.pid = Some(10000 + id);
                t.program_started_ms = Some(now_ms());
                t.status = Some(crate::status::Status {
                    state: "done".into(),
                    kind: None,
                    progress: None,
                    app: "fixture".into(),
                    title: String::new(),
                    msg: String::new(),
                });
                id
            })
            .collect::<Vec<_>>()
    };
    if matches!(mode, "wait_ack" | "bad_ack" | "never_ack") {
        let (writer, frames) = mpsc::channel();
        let (bye, _) = mpsc::channel();
        {
            let mut st = core.lock();
            st.holders.push(Link {
                writer,
                pid: 0,
                instance: "close-fixture".into(),
                current: true,
                bye,
                bye_rx: None,
            });
            for id in &ids {
                st.reg.terminals.get_mut(id).unwrap().holder = Some("close-fixture".into());
            }
        }
        let observed = core.clone();
        let observed_ids = ids.clone();
        let lease_file = root.join("lease");
        std::thread::spawn(move || {
            if frames.recv_timeout(Duration::from_secs(10)).is_ok() {
                assert!(lease_file.exists());
                let mut st = observed.lock();
                for id in observed_ids {
                    observed.record_finish(&mut st, id, Exit { code: Some(0), signal: None }, "exited");
                }
                observed.save(&st);
                observed.changed.notify_waiters();
            }
        });
    }
    (core, root, ids)
}

#[tokio::test]
async fn configured_close_denial_never_changes_targets_or_stopping_state() {
    for mode in ["denied", "oversized", "eof"] {
        let (core, root, ids) = close_fixture(mode);
        let before = serde_json::to_value(&core.lock().reg.terminals).unwrap();
        assert!(core.kill(&ids).await.is_err());
        assert_eq!(serde_json::to_value(&core.lock().reg.terminals).unwrap(), before);
        assert!(core.lock().killing.is_empty());
        assert!(core.shutdown().await.is_err());
        assert!(!core.lock().stopping);
        drop(core);
        remove_root(root);
    }
}

#[tokio::test]
async fn guarded_shutdown_and_new_terminal_admission_have_only_two_atomic_outcomes() {
    for _ in 0..64 {
        let (mut core, root) = test_core();
        Arc::get_mut(&mut core).unwrap().close_guard = Some(vec!["must-not-run".into()]);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let closing = core.clone();
        let closing_barrier = barrier.clone();
        let stop = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            closing_barrier.wait();
            runtime.block_on(closing.shutdown())
        });
        let starting = core.clone();
        let starting_barrier = barrier.clone();
        let run = std::thread::spawn(move || {
            starting_barrier.wait();
            let mut st = starting.lock();
            // The production run admission check and registry insertion share
            // this lock. No real program is needed to exercise the boundary.
            crate::api::not_stopping(&st)?;
            st.reg
                .create(crate::terminals::NewTerminal { argv: vec!["fixture".into()], ..Default::default() }, now_ms())
        });
        barrier.wait();
        let stopped = stop.join().unwrap().is_ok();
        let admitted = run.join().unwrap().is_ok();
        let st = core.lock();
        assert_ne!(stopped, admitted, "shutdown or terminal admission must win, never both");
        assert_eq!(st.stopping, stopped, "a denied shutdown must leave stopping unchanged");
        assert_eq!(st.reg.terminals.values().any(|t| t.is_live()), admitted);
        assert!(st.killing.is_empty());
        drop(st);
        drop(core);
        remove_root(root);
    }
}

#[tokio::test]
async fn input_or_new_child_between_snapshot_and_ready_cancels_the_whole_close() {
    for add_child in [false, true] {
        let (core, root, ids) = close_fixture("wait");
        let requested = root.join("request.json");
        let changed = core.clone();
        let go = root.join("go");
        let parent = ids[0];
        let changing = tokio::spawn(async move {
            for _ in 0..500 {
                if requested.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(requested.exists());
            {
                let mut st = changed.lock();
                if add_child {
                    st.reg
                        .create(
                            crate::terminals::NewTerminal {
                                argv: vec!["fixture".into()],
                                parent: Some(crate::terminals::address(parent)),
                                ..Default::default()
                            },
                            now_ms(),
                        )
                        .unwrap();
                } else {
                    st.gates.entry(parent).or_default().viewer(b"new task", true);
                    st.note_input(parent).unwrap();
                }
            }
            std::fs::write(go, "ready").unwrap();
        });
        assert!(core.kill(&ids).await.is_err());
        changing.await.unwrap();
        assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
        assert!(core.lock().killing.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(root.join("outcome.json")).unwrap()).unwrap()["state"],
            "cancelled"
        );
        drop(core);
        remove_root(root);
    }
}

#[tokio::test]
async fn batch_endpoint_requires_a_configured_authorizer_even_without_live_targets() {
    let (core, root) = test_core();
    let call = crate::api::Call { core: &core, conn: None, plain: None };
    let error =
        crate::api::dispatch(&call, "terminal.kill_batch", json!({"roots":[],"expected":[]})).await.unwrap_err();
    assert!(matches!(error.kind.as_str(), "close_denied" | "close_retry_safe"));
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn close_receipt_requires_final_ack_and_preserves_rm_records_and_fences_until_then() {
    let (core, root, ids) = close_fixture("wait_ack");
    {
        let mut st = core.lock();
        for id in &ids {
            st.reg.terminals.get_mut(id).unwrap().rm = true;
        }
    }
    let closer = core.clone();
    let roots: Vec<_> = ids.iter().map(|id| crate::terminals::address(*id)).collect();
    let closing = tokio::spawn(async move { closer.guarded_close(roots, None, json!({"mode":"automatic"})).await });
    for _ in 0..500 {
        if root.join("outcome.json").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(root.join("outcome.json").exists());
    assert!(root.join("lease").exists(), "authorizer must retain its lease through native outcome");
    assert!(!closing.is_finished(), "no receipt before final ACK");
    {
        let mut st = core.lock();
        assert_eq!(st.close_inflight.len(), ids.len());
        assert!(crate::api::not_stopping(&st).is_ok());
        assert!(st.close_blocks(&crate::terminals::address(ids[0])));
        for id in &ids {
            let t = st.reg.terminals.get(id).unwrap();
            assert!(!t.is_live());
            assert_eq!(t.pid, Some(10000 + id));
            core.remove(&mut st, *id);
            assert!(st.reg.terminals.contains_key(id));
        }
    }
    assert!(core.keys(ids[0], &["enter".into()]).await.is_err());
    let request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap();
    assert_eq!(request["context"]["mode"], "automatic");
    assert_eq!(request["core_id"], "test");
    assert_eq!(request["targets"][0]["machine_id"], "test");
    std::fs::write(root.join("go_ack"), "acknowledge").unwrap();
    let closed = closing.await.unwrap().unwrap();
    assert_eq!(closed.len(), ids.len());
    assert!(core.lock().close_inflight.is_empty());
    assert_eq!(core.lock().close_verified.len(), ids.len());
    assert!(!root.join("lease").exists());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn bad_final_ack_never_returns_success_or_reuses_the_close_permit() {
    let (core, root, ids) = close_fixture("bad_ack");
    assert!(core.kill(&ids).await.is_err());
    assert_eq!(core.lock().close_inflight.len(), ids.len());
    assert!(core.lock().close_verified.is_empty());
    assert!(core.kill(&ids).await.is_err());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn a_lost_holder_without_an_exit_observation_is_not_a_committed_close() {
    let (core, root, ids) = close_fixture("ok");
    assert!(core.kill(&ids).await.is_err());
    assert!(!root.join("outcome.json").exists(), "must not send committed without actual exit evidence");
    assert!(core.lock().close_verified.is_empty());
    drop(core);
    remove_root(root);
}

#[tokio::test(start_paused = true)]
async fn authorizer_deadline_denies_without_sending_a_signal() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let (core, root, ids) = close_fixture("never_ready");
    {
        let closing = core.kill(&ids);
        tokio::pin!(closing);
        poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(121)).await;
        assert!(closing.await.is_err());
    }
    assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
    assert!(core.lock().close_inflight.is_empty());
    assert!(core.lock().killing.is_empty());
    tokio::time::resume(); // reconciliation includes real filesystem persistence
    let (op, record) = core.lock().reg.close_operations.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
    let proof = core.close_reconcile(op, record.roots, record.expected, json!({})).await.unwrap();
    assert_eq!(proof["no_signal"], true);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn lost_ack_reconciliation_uses_the_original_operation_without_killing_again() {
    let (core, root, ids) = close_fixture("bad_ack");
    assert!(core.kill(&ids).await.is_err());
    let (operation, original) =
        core.lock().reg.close_operations.iter().next().map(|(id, op)| (id.clone(), op.clone())).unwrap();
    let before = serde_json::to_value(&core.lock().reg.terminals).unwrap();
    let mut wrong = original.expected.clone();
    wrong[0].created_ms += 1;
    assert!(core.close_reconcile(operation.clone(), original.roots.clone(), wrong, json!({})).await.is_err());
    assert_eq!(core.lock().close_inflight.len(), ids.len());
    let reply =
        core.close_reconcile(operation.clone(), original.roots, original.expected.clone(), json!({})).await.unwrap();
    assert_eq!(reply["operation_id"], operation);
    assert_eq!(reply["terminated"], json!(original.expected));
    assert_eq!(serde_json::to_value(&core.lock().reg.terminals).unwrap(), before);
    assert!(core.lock().close_inflight.is_empty());
    assert!(core.lock().killing.is_empty());
    assert!(core.lock().reg.close_operations[&operation].acknowledged);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn reconcile_never_releases_a_partial_or_unwitnessed_operation() {
    let (core, root, ids) = close_fixture("ok");
    assert!(core.kill(&ids).await.is_err()); // no actual Exit was reported by this fixture
    let (id, op) = core.lock().reg.close_operations.iter().next().map(|(id, op)| (id.clone(), op.clone())).unwrap();
    assert!(core.close_reconcile(id, op.roots, op.expected, json!({})).await.is_err());
    assert_eq!(core.lock().close_inflight.len(), ids.len());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn definite_pre_ready_denial_has_only_a_no_signal_abort_receipt() {
    let (core, root, ids) = close_fixture("denied");
    let roots = ids.iter().map(|id| crate::terminals::address(*id)).collect();
    let error = core.close_transaction(roots, None, json!({}), Some("caller-known-denial".into())).await.unwrap_err();
    assert_eq!(error.kind, "close_retry_safe");
    let original = core.lock().reg.close_operations["caller-known-denial"].clone();
    let reply = core
        .close_reconcile("caller-known-denial".into(), original.roots, original.expected.clone(), json!({}))
        .await
        .unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["no_signal"], true);
    assert_eq!(reply["expected"], json!(original.expected));
    assert!(reply.get("terminated").is_none());
    assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
    assert!(core.lock().killing.is_empty());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn close_snapshot_is_read_only_and_a_natural_exit_is_not_a_close_authorization() {
    let (core, root, ids) = close_fixture("denied");
    let roots = vec![crate::terminals::address(ids[0])];
    let first = core.close_snapshot(&roots).unwrap();
    let generation = first["targets"][0]["input_generation"].as_u64().unwrap();
    assert_eq!(first["core_id"], "test");
    assert!(core.lock().reg.close_operations.is_empty());
    {
        let mut st = core.lock();
        st.note_input(ids[0]).unwrap();
        core.record_finish(&mut st, ids[0], Exit { code: Some(0), signal: None }, "exited");
        core.save(&st);
    }
    let ended = core.close_snapshot(&roots).unwrap();
    assert_eq!(ended["targets"][0]["native_state"], "finished");
    assert_eq!(ended["targets"][0]["observed_exit"], true);
    assert_eq!(ended["targets"][0]["input_generation"], generation + 1);
    assert!(core.close_reconcile("no-original-operation".into(), roots, vec![], json!({})).await.is_err());
    assert!(core.lock().reg.close_operations.is_empty());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn native_preflight_denial_preserves_a_no_signal_proof_but_never_overwrites_an_existing_operation() {
    let (core, root, ids) = close_fixture("denied");
    let roots = vec![crate::terminals::address(ids[0])];
    let mut expected: Vec<crate::close_guard_plan::Identity> =
        serde_json::from_value(core.close_snapshot(&roots).unwrap()["expected"].clone()).unwrap();
    expected[0].created_ms += 1;
    let op = "preflight-proof".to_string();
    assert!(core.close_transaction(roots.clone(), Some(expected.clone()), json!({}), Some(op.clone())).await.is_err());
    let proof = core.close_reconcile(op.clone(), roots.clone(), expected.clone(), json!({})).await.unwrap();
    assert_eq!(proof["no_signal"], true);
    assert_eq!(proof["expected"], json!(expected));
    assert!(proof.get("terminated").is_none());
    {
        let mut st = core.lock();
        let original = st.reg.close_operations.get_mut(&op).unwrap();
        original.cancelled = false;
        original.signalled = true;
    }
    assert!(core.close_transaction(roots.clone(), Some(expected.clone()), json!({}), Some(op.clone())).await.is_err());
    assert!(core.close_reconcile(op, roots, expected, json!({})).await.is_err());
    assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn lost_ack_reconciliation_survives_a_core_restart_with_the_original_exit_proof() {
    let (core, root, ids) = close_fixture("bad_ack");
    assert!(core.kill(&ids).await.is_err());
    let (operation, original) =
        core.lock().reg.close_operations.iter().next().map(|(id, op)| (id.clone(), op.clone())).unwrap();
    let argv = core.close_guard.as_ref().unwrap();
    std::fs::write(&core.paths.config, format!("close_guard = {}\n", serde_json::to_string(argv).unwrap())).unwrap();
    core.flush_saved().await.unwrap();
    let paths = Paths {
        state: core.paths.state.clone(),
        config: core.paths.config.clone(),
        socket: core.paths.socket.clone(),
        holder_socket: core.paths.holder_socket.clone(),
    };
    drop(core);
    let recovered = Core::start(paths, CoreInfo { id: "test".into(), name: "test".into() }).unwrap();
    assert_eq!(recovered.lock().close_inflight.len(), ids.len());
    let snapshot = recovered.close_snapshot(&original.roots).unwrap();
    assert_eq!(snapshot["targets"][0]["observed_exit"], true);
    let receipt = recovered
        .close_reconcile(operation.clone(), original.roots, original.expected.clone(), json!({}))
        .await
        .unwrap();
    assert_eq!(receipt["operation_id"], operation);
    assert_eq!(receipt["terminated"], json!(original.expected));
    assert!(recovered.lock().close_inflight.is_empty());
    drop(recovered);
    remove_root(root);
}

#[tokio::test]
async fn input_generation_epoch_is_durable_and_does_not_reuse_an_old_boot_generation() {
    let (core, root) = test_core();
    let first_epoch = core.lock().reg.input_epoch;
    core.flush_saved().await.unwrap();
    let paths = Paths {
        state: core.paths.state.clone(),
        config: core.paths.config.clone(),
        socket: core.paths.socket.clone(),
        holder_socket: core.paths.holder_socket.clone(),
    };
    drop(core);
    let recovered = Core::start(paths, CoreInfo { id: "test".into(), name: "test".into() }).unwrap();
    let mut st = recovered.lock();
    assert!(st.reg.input_epoch > first_epoch);
    let id = st
        .reg
        .create(crate::terminals::NewTerminal { argv: vec!["fixture".into()], ..Default::default() }, now_ms())
        .unwrap();
    assert!(st.reg.terminals[&id].input_generation > (first_epoch << 32) + u32::MAX as u64);
    drop(st);
    drop(recovered);
    remove_root(root);
}

#[tokio::test]
async fn natural_exit_audit_is_signal_free_and_requires_every_actual_exit_and_fresh_helper_ack() {
    let (core, root, ids) = close_fixture("denied");
    let roots: Vec<_> = ids.iter().map(|id| crate::terminals::address(*id)).collect();
    let expected: Vec<crate::close_guard_plan::Identity> =
        serde_json::from_value(core.close_snapshot(&roots).unwrap()["expected"].clone()).unwrap();
    assert!(core.close_reconcile("audit-live".into(), roots.clone(), expected.clone(), json!({})).await.is_err());
    assert!(core.lock().reg.close_operations.is_empty());
    {
        let mut st = core.lock();
        for &id in &ids {
            core.record_finish(&mut st, id, Exit { code: Some(0), signal: None }, "exited");
        }
        core.save(&st);
    }
    // An actual Exit alone does not bypass external prebinding/audit policy.
    assert!(core.close_reconcile("audit-ended".into(), roots.clone(), expected.clone(), json!({})).await.is_err());
    let request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap();
    assert_eq!(request["action"], "audit");
    assert_eq!(request["context"]["mode"], "reconcile");
    assert!(request["targets"].as_array().unwrap().iter().all(|t| t["observed_exit"] == true));
    assert!(!core.lock().reg.close_operations["audit-ended"].signalled);
    assert!(core.lock().killing.is_empty());
    assert!(!core.lock().reg.close_operations["audit-ended"].acknowledged);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn unknown_holder_or_late_spawn_is_retained_instead_of_being_killed_without_a_native_identity() {
    let (core, root, _) = close_fixture("denied");
    let (writer, frames) = mpsc::channel();
    let (bye, _) = mpsc::channel();
    {
        let mut st = core.lock();
        st.holders.push(Link { writer, pid: 0, instance: "orphan".into(), current: true, bye, bye_rx: None });
        let welcome = proto::Welcome {
            version: proto::VERSION,
            instance: "orphan".into(),
            pid: 0,
            build: String::new(),
            previous: "crash".into(),
            terminals: vec![proto::HeldTerminal { id: 99, pid: 20000, cols: 80, rows: 24, exit: None }],
        };
        core.adopt(&mut st, &welcome, HashMap::new());
        core.spawn_result(&mut st, "orphan", 98, Ok(20001));
        assert!(st.close_unverified_orphan);
    }
    assert!(frames.try_recv().is_err(), "unverifiable orphan must receive neither SIGNAL nor RELEASE");
    assert!(core.shutdown().await.is_err());
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn pre_ready_protocol_failures_settle_only_the_exact_durable_no_signal_operation() {
    for mode in ["eof", "oversized"] {
        let (core, root, ids) = close_fixture(mode);
        assert!(core.kill(&ids).await.is_err());
        let (op, record) = core.lock().reg.close_operations.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        assert!(!record.signalled && !record.cancelled);
        let mut wrong = record.expected.clone();
        wrong[0].pid += 1;
        assert!(core.close_reconcile(op.clone(), record.roots.clone(), wrong, json!({})).await.is_err());
        assert!(!core.lock().reg.close_operations[&op].cancelled);
        let proof = core.close_reconcile(op.clone(), record.roots, record.expected.clone(), json!({})).await.unwrap();
        assert_eq!(proof["no_signal"], true);
        assert_eq!(proof["expected"], json!(record.expected));
        assert!(proof.get("terminated").is_none());
        assert!(core.lock().reg.close_operations[&op].cancelled);
        assert!(core.lock().close_inflight.is_empty());
        assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
        // Fresh requests can reach policy again, rather than the old global hold.
        assert!(core.kill(&ids).await.is_err());
        assert_eq!(core.lock().reg.close_operations.len(), 2);
        drop(core);
        remove_root(root);
    }
}

#[tokio::test]
async fn rejected_natural_audit_is_durably_cancelled_and_does_not_fence_unrelated_kept_recovery() {
    let (core, root, ids) = close_fixture("denied");
    let roots: Vec<_> = ids.iter().map(|id| crate::terminals::address(*id)).collect();
    let expected: Vec<crate::close_guard_plan::Identity> =
        serde_json::from_value(core.close_snapshot(&roots).unwrap()["expected"].clone()).unwrap();
    {
        let mut st = core.lock();
        for id in &ids {
            core.record_finish(&mut st, *id, Exit { code: Some(0), signal: None }, "exited");
        }
    }
    let error =
        core.close_reconcile("audit-rejected".into(), roots.clone(), expected.clone(), json!({})).await.unwrap_err();
    assert_eq!(error.kind, "close_retry_safe");
    let proof = core.close_reconcile("audit-rejected".into(), roots, expected.clone(), json!({})).await.unwrap();
    assert_eq!(proof["no_signal"], true);
    assert_eq!(proof["expected"], json!(expected));
    let mut st = core.lock();
    assert!(st.reg.close_operations["audit-rejected"].cancelled);
    assert!(st.close_inflight.is_empty());
    st.close_inflight.insert(ids[0]);
    let kept = st
        .reg
        .create(crate::terminals::NewTerminal { argv: vec!["sh".into()], keep: true, ..Default::default() }, now_ms())
        .unwrap();
    assert!(!st.close_blocks(&crate::terminals::address(kept)));
    assert!(st.close_blocks(&crate::terminals::address(ids[0])));
    drop(st);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn unobserved_post_signal_exit_stays_held_without_blocking_disjoint_terminals() {
    let (core, root, ids) = close_fixture("ok");
    assert!(core.kill(&ids).await.is_err());
    let (op, record) = core.lock().reg.close_operations.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
    assert!(record.signalled);
    let snapshot = core.close_snapshot(&record.roots).unwrap();
    assert_eq!(snapshot["targets"][0]["native_state"], "unknown");
    assert_eq!(snapshot["operations"][0]["outcome"], "exit_unobserved");
    assert!(core.close_reconcile(op.clone(), record.roots, record.expected, json!({})).await.is_err());
    let other = {
        let mut st = core.lock();
        let other = st
            .reg
            .create(
                crate::terminals::NewTerminal { argv: vec!["sh".into()], keep: true, ..Default::default() },
                now_ms(),
            )
            .unwrap();
        let t = st.reg.terminals.get_mut(&other).unwrap();
        t.pid = Some(33000);
        t.program_started_ms = Some(now_ms());
        assert!(!st.close_blocks(&crate::terminals::address(other)));
        other
    };
    let error = core
        .close_transaction(vec![crate::terminals::address(other)], Some(vec![]), json!({}), Some("other-op".into()))
        .await
        .unwrap_err();
    assert_eq!(error.kind, "close_retry_safe", "unrelated requests must reach their own preflight");
    assert!(core.lock().close_inflight.contains(&ids[0]));
    assert!(!core.lock().reg.close_operations[&op].cancelled);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn a_failed_pre_signal_cancel_ack_can_be_settled_from_native_intent_without_reusing_the_permit() {
    let (core, root, ids) = close_fixture("bad_cancel");
    let closing_core = core.clone();
    let closing_ids = ids.clone();
    let closing = tokio::spawn(async move { closing_core.kill(&closing_ids).await });
    // Preparation includes durable disk IO (up to 10s) and Python startup.
    // Await the actual protocol stage, not a shorter five-second fixture race.
    let preparation = tokio::time::Instant::now() + Duration::from_secs(30);
    while !root.join("request.json").exists() {
        if closing.is_finished() {
            panic!("close ended before authorizer request: {:?}", closing.await);
        }
        assert!(tokio::time::Instant::now() < preparation, "authorizer never received its request");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    core.lock().note_input(ids[0]).unwrap();
    std::fs::write(root.join("go"), "ready").unwrap();
    assert!(closing.await.unwrap().is_err());
    let outcome: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("outcome.json")).unwrap()).unwrap();
    assert_eq!(outcome["state"], "cancelled", "this regression must exercise an actual cancellation ACK failure");
    let (op, record) = core.lock().reg.close_operations.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
    assert!(!record.signalled && !record.cancelled);
    let proof = core.close_reconcile(op, record.roots, record.expected, json!({})).await.unwrap();
    assert_eq!(proof["no_signal"], true);
    assert!(core.lock().killing.is_empty());
    assert!(core.lock().reg.terminals.values().all(|t| t.is_live()));
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn unrelated_lost_kept_terminal_really_reaches_spawn_while_an_uncertain_target_remains_fenced() {
    let (core, root, ids) = close_fixture("denied");
    std::fs::write(&core.paths.config, "shell = [\"fixture\"]\n").unwrap();
    let (writer, frames) = mpsc::channel();
    let (bye, _) = mpsc::channel();
    let other = {
        let mut st = core.lock();
        st.close_inflight.insert(ids[0]);
        st.reg.terminals.get_mut(&ids[0]).unwrap().keep = true;
        st.reg.finish(ids[0], None, None, "holder_lost", now_ms());
        let other = st
            .reg
            .create(
                crate::terminals::NewTerminal { argv: vec!["sh".into()], keep: true, ..Default::default() },
                now_ms(),
            )
            .unwrap();
        st.reg.finish(other, None, None, "holder_lost", now_ms());
        st.reg.terminals.get_mut(&other).unwrap().restart_after_ms = 0;
        st.holders.push(Link { writer, pid: 0, instance: "recover-fixture".into(), current: true, bye, bye_rx: None });
        other
    };
    core.clone().recover_kept(false).await;
    let frame = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    let (kind, id, _) = proto::read(&mut frame.as_slice()).unwrap().unwrap();
    assert_eq!(kind, proto::SPAWN);
    assert_eq!(id, other);
    assert!(frames.try_recv().is_err());
    let st = core.lock();
    assert_eq!(st.reg.terminals[&other].holder.as_deref(), Some("recover-fixture"));
    assert!(st.reg.terminals[&ids[0]].holder.is_none());
    assert!(st.close_inflight.contains(&ids[0]));
    drop(st);
    drop(core);
    remove_root(root);
}

#[tokio::test]
async fn persisted_pre_ready_failure_can_settle_after_restart_without_inventing_termination() {
    let (core, root, _) = close_fixture("eof");
    let roots = vec!["t1".to_string()];
    let expected: Vec<crate::close_guard_plan::Identity> =
        serde_json::from_value(core.close_snapshot(&roots).unwrap()["expected"].clone()).unwrap();
    assert!(
        core.close_transaction(roots.clone(), Some(expected.clone()), json!({}), Some("restart-no-signal".into()))
            .await
            .is_err()
    );
    std::fs::write(
        &core.paths.config,
        format!("close_guard = {}\n", serde_json::to_string(core.close_guard.as_ref().unwrap()).unwrap()),
    )
    .unwrap();
    core.flush_close_saved().await.unwrap();
    let paths = Paths {
        state: core.paths.state.clone(),
        config: core.paths.config.clone(),
        socket: core.paths.socket.clone(),
        holder_socket: core.paths.holder_socket.clone(),
    };
    drop(core);
    let recovered = Core::start(paths, CoreInfo { id: "test".into(), name: "test".into() }).unwrap();
    let native_before = serde_json::to_value(&recovered.lock().reg.terminals).unwrap();
    let proof =
        recovered.close_reconcile("restart-no-signal".into(), roots, expected.clone(), json!({})).await.unwrap();
    assert_eq!(proof["no_signal"], true);
    assert_eq!(proof["expected"], json!(expected));
    assert!(proof.get("terminated").is_none());
    assert!(!recovered.lock().reg.close_operations["restart-no-signal"].signalled);
    assert_eq!(serde_json::to_value(&recovered.lock().reg.terminals).unwrap(), native_before);
    assert!(recovered.lock().reg.close_witnesses.is_empty(), "restart loss is not an actual Exit");
    drop(recovered);
    remove_root(root);
}
