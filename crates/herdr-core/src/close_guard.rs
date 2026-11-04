//! External policy lease. Core supplies and fences the complete native snapshot.
use crate::close_guard_plan::{self as plan, Identity, Target};
use crate::rpc::RpcError;
use crate::runtime::{Core, State};
use serde_json::{Value, json};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const LIMIT: usize = 256 * 1024;
static OPERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn denied(message: impl Into<String>) -> RpcError {
    RpcError::new("close_denied", message, "complete the external close policy; no single-kill fallback")
}

fn targets(st: &State) -> Result<Vec<Target>, RpcError> {
    st.reg
        .terminals
        .values()
        .filter(|t| t.is_live())
        .map(|t| {
            let gate = st.gates.get(&t.id());
            // Unrelated busy terminals need not block a selected subtree: encode their
            // pending state in the fingerprint and reject it only after selection.
            let pending =
                gate.is_some_and(|g| !g.close_ready()) || st.queues.get(&t.id()).is_some_and(|q| q.try_lock().is_err());
            Ok(Target {
                identity: Identity { address: t.address.clone(), pid: t.pid.unwrap_or(0), created_ms: t.created_ms },
                parent: t.parent.clone(),
                input_generation: t.input_generation,
                program_started_ms: t.program_started_ms.unwrap_or(0),
                turn: t.turn,
                state: if pending {
                    "pending_input".into()
                } else {
                    t.status.as_ref().map_or("unknown", |s| &s.state).into()
                },
                protected: t.keep && t.labels.contains_key("herdr.space"),
            })
        })
        .collect()
}

struct Lease {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    operation: String,
    token: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Close,
    Reconcile,
    Audit,
}

impl Lease {
    async fn open(
        core: &Core,
        operation: String,
        roots: &[String],
        expected: &[Identity],
        before: &[Target],
        context: Value,
        phase: Phase,
    ) -> Result<Self, RpcError> {
        let config =
            core.close_guard.as_ref().ok_or_else(|| retry_safe("transactional close authorizer is not configured"))?;
        if config.first().is_none_or(|s| s.is_empty()) {
            return Err(retry_safe("invalid close authorizer configuration"));
        }
        let mut command = Command::new(&config[0]);
        command
            .args(&config[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("HC_") {
                command.env_remove(key);
            }
        }
        command.env("HC_SOCKET", &core.paths.socket).env("PYTHONIOENCODING", "utf-8").env("PYTHONUTF8", "1");
        if let Some(session) = &core.close_session {
            command.env("HC_SESSION", session);
        }
        let mut child = command.spawn().map_err(|e| denied(format!("cannot start close authorizer: {e}")))?;
        let input = child.stdin.take().ok_or_else(|| denied("missing close authorizer stdin"))?;
        let output = BufReader::new(child.stdout.take().ok_or_else(|| denied("missing close authorizer stdout"))?);
        let mut lease = Lease { child, input, output, operation, token: String::new() };
        let identities: Vec<_> = before
            .iter()
            .map(|t| {
                json!({"address":t.identity.address,"pid":t.identity.pid,
            "created_ms":t.identity.created_ms,"machine_id":core.info.id,"input_generation":t.input_generation,
            "program_started_ms":t.program_started_ms,"turn":t.turn,"state":t.state,"parent":t.parent,
            "observed_exit":phase != Phase::Close})
            })
            .collect();
        lease
            .write(&json!({"version":1,"operation_id":lease.operation,"core_id":core.info.id,
            "roots":roots,"expected":expected,"targets":identities,"complete":true,"context":context,
            "action":if phase == Phase::Audit {"audit"} else {"close"}}))
            .await?;
        let ready = lease.read(120).await?;
        if ready["state"] == "denied" && ready["allow"] == false {
            let status = tokio::time::timeout(Duration::from_secs(30), lease.child.wait())
                .await
                .map_err(|_| denied("denial process did not exit"))?
                .map_err(|e| denied(e.to_string()))?;
            return Err(if status.code() == Some(1) {
                retry_safe("authorizer denied before READY")
            } else {
                denied("unconfirmed denial outcome")
            });
        }
        let token = ready["token"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| denied("missing close token"))?;
        if ready["state"] != "ready" || ready["allow"] != true || ready["targets"] != json!(identities) {
            return Err(denied("close authorizer did not approve the exact target set"));
        }
        lease.token = token.into();
        Ok(lease)
    }

    async fn write(&mut self, value: &Value) -> Result<(), RpcError> {
        let mut bytes = serde_json::to_vec(value).map_err(|e| denied(e.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() > LIMIT {
            return Err(denied("close protocol line exceeds limit"));
        }
        tokio::time::timeout(Duration::from_secs(30), self.input.write_all(&bytes))
            .await
            .map_err(|_| denied("close authorizer write timed out"))?
            .map_err(|e| denied(e.to_string()))
    }

    async fn read(&mut self, seconds: u64) -> Result<Value, RpcError> {
        let mut bytes = Vec::new();
        let mut bounded = (&mut self.output).take((LIMIT + 1) as u64);
        tokio::time::timeout(Duration::from_secs(seconds), bounded.read_until(b'\n', &mut bytes))
            .await
            .map_err(|_| denied("close authorizer timed out"))?
            .map_err(|e| denied(e.to_string()))?;
        if bytes.len() > LIMIT || bytes.last() != Some(&b'\n') {
            return Err(denied("missing or oversized close protocol line"));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| denied(e.to_string()))?;
        if value["version"].as_u64() != Some(1) || value["operation_id"].as_str() != Some(&self.operation) {
            return Err(denied("close protocol version or operation mismatch"));
        }
        Ok(value)
    }

    async fn outcome(&mut self, committed: bool) -> Result<(), RpcError> {
        self.write(&json!({"state": if committed {"committed"} else {"cancelled"},
            "operation_id": self.operation, "token": self.token}))
            .await?;
        let ack = self.read(30).await?;
        let status = tokio::time::timeout(Duration::from_secs(30), self.child.wait())
            .await
            .map_err(|_| denied("close authorizer did not exit"))?
            .map_err(|e| denied(e.to_string()))?;
        if ack["allow"] == false
            && ((committed && ack["state"] == "closed" && status.success())
                || (!committed && ack["state"] == "cancelled" && status.code() == Some(1)))
        {
            Ok(())
        } else {
            Err(denied("close outcome not acknowledged as closed"))
        }
    }
}

fn retry_safe(message: impl Into<String>) -> RpcError {
    RpcError::new(
        "close_retry_safe",
        message,
        "verified no-signal outcome; a new operation may be attempted after readiness",
    )
}

fn valid_operation(id: &str) -> bool {
    !id.is_empty() && id.len() <= 80 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn same_set<T: Ord + Clone>(a: &[T], b: &[T]) -> bool {
    let left: std::collections::BTreeSet<_> = a.iter().cloned().collect();
    let right: std::collections::BTreeSet<_> = b.iter().cloned().collect();
    left.len() == a.len() && right.len() == b.len() && left == right
}

impl Core {
    pub(crate) async fn guarded_close(
        &self,
        roots: Vec<String>,
        expected: Option<Vec<Identity>>,
        context: Value,
    ) -> Result<Vec<Identity>, RpcError> {
        Ok(self.close_transaction(roots, expected, context, None).await?.terminated)
    }

    fn save_operation(&self, operation: &str, record: plan::CloseOperation) {
        let mut st = self.lock();
        st.reg.close_operations.insert(operation.into(), record);
        self.save(&st);
    }

    async fn cancel_before_signal(&self, lease: &mut Lease, ids: &[u32]) -> Result<(), RpcError> {
        let cancelled = lease.outcome(false).await.is_ok();
        {
            let mut st = self.lock();
            if let Some(record) = st.reg.close_operations.get_mut(&lease.operation) {
                record.signalled = false;
                record.cancelled = cancelled;
            }
            for id in ids {
                st.close_inflight.remove(id);
                st.killing.remove(id);
            }
            self.save(&st);
        }
        self.flush_close_saved().await?;
        if cancelled { Ok(()) } else { Err(denied("pre-signal cancellation was not acknowledged")) }
    }

    pub(crate) async fn close_transaction(
        &self,
        roots: Vec<String>,
        expected: Option<Vec<Identity>>,
        context: Value,
        supplied: Option<String>,
    ) -> Result<crate::api::KillBatchResult, RpcError> {
        let operation = supplied.unwrap_or_else(|| {
            format!(
                "c{}_{}_{}",
                std::process::id(),
                crate::runtime::now_ms(),
                OPERATION.fetch_add(1, Ordering::Relaxed)
            )
        });
        if !valid_operation(&operation) {
            return Err(retry_safe("invalid close operation ID"));
        }
        let result = self.perform_close_transaction(roots.clone(), expected.clone(), context, operation.clone()).await;
        // A well-formed caller can recover even a native preflight refusal. Only
        // this invocation's previously unseen operation can receive this proof;
        // an existing uncertain operation is never rewritten as cancelled.
        if result.is_err()
            && let Some(expected) = expected
        {
            let recorded = {
                let mut st = self.lock();
                if let std::collections::btree_map::Entry::Vacant(entry) = st.reg.close_operations.entry(operation) {
                    entry.insert(plan::CloseOperation {
                        roots,
                        expected,
                        targets: vec![],
                        observed_exits: Default::default(),
                        acknowledged: false,
                        signalled: false,
                        cancelled: true,
                        audit_only: false,
                    });
                    self.save(&st);
                    true
                } else {
                    false
                }
            };
            if recorded {
                self.flush_close_saved().await?;
            }
        }
        result
    }

    async fn perform_close_transaction(
        &self,
        roots: Vec<String>,
        expected: Option<Vec<Identity>>,
        context: Value,
        operation: String,
    ) -> Result<crate::api::KillBatchResult, RpcError> {
        let _serial = self.close_serial.try_lock().map_err(|_| denied("another close transaction is in progress"))?;
        let (before, generation) = {
            let st = self.lock();
            if st.reg.close_operations.contains_key(&operation) {
                return Err(denied("operation already exists; reconcile the original operation"));
            }
            if st.reg.close_operations.values().any(|op| !op.acknowledged && !op.cancelled) {
                return Err(denied("an earlier close outcome is unresolved"));
            }
            (plan::closure(&roots, &targets(&st)?).map_err(retry_safe)?, st.policy_generation)
        };
        let expected = expected.unwrap_or_else(|| before.iter().map(|t| t.identity.clone()).collect());
        plan::plan(&roots, &expected, &before).map_err(retry_safe)?;
        if before.iter().any(|t| t.state == "pending_input") {
            return Err(retry_safe("target input is pending"));
        }
        if before.len() > 512 {
            return Err(retry_safe("too many close targets"));
        }
        self.save_operation(
            &operation,
            plan::CloseOperation {
                roots: roots.clone(),
                expected: expected.clone(),
                targets: before.clone(),
                observed_exits: Default::default(),
                acknowledged: false,
                signalled: false,
                cancelled: false,
                audit_only: false,
            },
        );
        self.flush_close_saved().await?;
        let mut lease =
            match Lease::open(self, operation.clone(), &roots, &expected, &before, context, Phase::Close).await {
                Ok(lease) => lease,
                Err(error) => {
                    if error.kind == "close_retry_safe" {
                        {
                            let mut st = self.lock();
                            st.reg.close_operations.get_mut(&operation).unwrap().cancelled = true;
                            self.save(&st);
                        }
                        self.flush_close_saved().await?;
                    }
                    return Err(error);
                }
            };
        let ids: Vec<_> = before
            .iter()
            .map(|t| crate::terminals::parse_id(&t.identity.address).expect("validated address"))
            .collect();
        let validate = |st: &State| -> Result<(), RpcError> {
            if st.policy_generation != generation {
                return Err(denied("focus, labels or document changed"));
            }
            plan::revalidate(&roots, &expected, &before, &targets(st)?).map_err(denied)
        };
        let ready_valid =
            lease.child.try_wait().map_err(|e| denied(e.to_string()))?.is_none() && validate(&self.lock()).is_ok();
        if !ready_valid {
            return match self.cancel_before_signal(&mut lease, &[]).await {
                Ok(()) => Err(retry_safe("native snapshot changed before commitment")),
                Err(e) => Err(e),
            };
        }
        let armed = (|| {
            let mut st = self.lock();
            validate(&st)?;
            st.close_inflight.extend(&ids);
            for id in &ids {
                st.close_observed_exit.remove(id);
            }
            st.reg.close_operations.get_mut(&operation).unwrap().signalled = true;
            self.save(&st); // durable signal intent precedes the first signal
            Ok::<(), RpcError>(())
        })();
        if armed.is_err() {
            return match self.cancel_before_signal(&mut lease, &[]).await {
                Ok(()) => Err(retry_safe("native snapshot changed before signal intent")),
                Err(e) => Err(e),
            };
        }
        if self.flush_close_saved().await.is_err() {
            let _ = self.cancel_before_signal(&mut lease, &ids).await;
            return Err(denied("could not persist native close intent"));
        }
        let committed = (|| {
            if lease.child.try_wait().map_err(|e| denied(e.to_string()))?.is_some() {
                return Err(denied("authorizer exited before commitment"));
            }
            let mut st = self.lock();
            validate(&st)?;
            st.killing.extend(&ids);
            for &id in &ids {
                self.signal(&st, id, crate::platform::signal::HUP);
            }
            Ok(())
        })();
        if let Err(error) = committed {
            return match self.cancel_before_signal(&mut lease, &ids).await {
                Ok(()) => Err(retry_safe(error.message)),
                Err(e) => Err(e),
            };
        }
        self.kill_authorized(&ids).await;
        {
            let st = self.lock();
            self.verify_ended(&st, &st.reg.close_operations[&operation])?;
        }
        self.flush_close_saved().await?;
        lease.outcome(true).await?;
        self.acknowledge_close(&operation, &ids)?;
        self.flush_close_saved().await?;
        Ok(crate::api::KillBatchResult { ok: true, operation_id: operation, terminated: expected })
    }

    fn verify_ended(&self, st: &State, record: &plan::CloseOperation) -> Result<(), RpcError> {
        let native_identities: Vec<_> = record.targets.iter().map(|t| t.identity.clone()).collect();
        if !same_set(&record.expected, &native_identities) {
            return Err(denied("stored native operation is incomplete"));
        }
        if (!record.signalled && !record.audit_only) || record.expected.len() != record.observed_exits.len() {
            return Err(denied("complete actual exit evidence is missing"));
        }
        for target in &record.targets {
            let address = &target.identity.address;
            let witness =
                st.reg.close_witnesses.get(address).ok_or_else(|| denied("native exit witness is missing"))?;
            if witness.target.identity != target.identity
                || witness.target.program_started_ms != target.program_started_ms
                || witness.target.input_generation != target.input_generation
                || (witness.code.is_none() && witness.signal.is_none())
                || !record.observed_exits.contains(address)
            {
                return Err(denied("native exit witness changed or is incomplete"));
            }
            if let Some(current) = st
                .reg
                .terminals
                .get(&crate::terminals::parse_id(address).ok_or_else(|| denied("invalid native identity"))?)
                && (current.is_live()
                    || current.pid != Some(target.identity.pid)
                    || current.created_ms != target.identity.created_ms
                    || current.program_started_ms != Some(target.program_started_ms)
                    || current.input_generation != target.input_generation)
            {
                return Err(denied("target is live or has changed identity"));
            }
        }
        Ok(())
    }

    fn acknowledge_close(&self, operation: &str, ids: &[u32]) -> Result<(), RpcError> {
        let mut st = self.lock();
        let record = st.reg.close_operations.get(operation).ok_or_else(|| denied("unknown native operation"))?;
        self.verify_ended(&st, record)?;
        st.reg.close_operations.get_mut(operation).unwrap().acknowledged = true;
        st.close_verified.extend(ids);
        for id in ids {
            st.close_inflight.remove(id);
            st.close_observed_exit.remove(id);
        }
        self.save(&st);
        Ok(())
    }

    pub(crate) async fn close_reconcile(
        &self,
        operation: String,
        roots: Vec<String>,
        expected: Vec<Identity>,
        context: Value,
    ) -> Result<Value, RpcError> {
        let _serial = self.close_serial.try_lock().map_err(|_| denied("another close transaction is in progress"))?;
        if !valid_operation(&operation) {
            return Err(denied("invalid operation ID"));
        }
        let record = {
            let mut st = self.lock();
            if let Some(record) = st.reg.close_operations.get(&operation) {
                record.clone()
            } else {
                // A new audit operation has no signal authority. Every selected
                // member must already have a durable native actual Exit witness.
                let mut all = targets(&st)?;
                for witness in st.reg.close_witnesses.values() {
                    if !all.iter().any(|t| t.identity.address == witness.target.identity.address) {
                        all.push(witness.target.clone());
                    }
                }
                let selected = plan::plan(&roots, &expected, &all).map_err(denied)?;
                let record = plan::CloseOperation {
                    roots: roots.clone(),
                    expected: expected.clone(),
                    targets: selected,
                    observed_exits: expected.iter().map(|t| t.address.clone()).collect(),
                    acknowledged: false,
                    signalled: false,
                    cancelled: false,
                    audit_only: true,
                };
                self.verify_ended(&st, &record)?;
                let ids = expected.iter().filter_map(|t| crate::terminals::parse_id(&t.address));
                st.close_inflight.extend(ids);
                st.reg.close_operations.insert(operation.clone(), record.clone());
                self.save(&st);
                record
            }
        };
        self.flush_close_saved().await?;
        if !same_set(&roots, &record.roots) || !same_set(&expected, &record.expected) {
            return Err(denied("reconcile does not match the original complete operation"));
        }
        if record.cancelled && !record.signalled {
            return Ok(
                json!({"ok":false,"operation_id":operation,"state":"cancelled","no_signal":true,"expected":record.expected}),
            );
        }
        let generation = {
            let st = self.lock();
            self.verify_ended(&st, &record)?;
            st.policy_generation
        };
        let mut context = context.as_object().cloned().unwrap_or_default();
        context.insert("mode".into(), json!("reconcile"));
        let mut lease = Lease::open(
            self,
            operation.clone(),
            &record.roots,
            &record.expected,
            &record.targets,
            Value::Object(context),
            if record.audit_only { Phase::Audit } else { Phase::Reconcile },
        )
        .await?;
        let valid = {
            let st = self.lock();
            st.policy_generation == generation && self.verify_ended(&st, &record).is_ok()
        };
        if !valid || lease.child.try_wait().map_err(|e| denied(e.to_string()))?.is_some() {
            // Original signals may already have been sent: EOF keeps that intent
            // unresolved; a cancellation must not relabel it as a no-signal close.
            return Err(denied("reconcile evidence changed"));
        }
        // No signal or kill call is reachable from this method.
        lease.outcome(true).await?;
        let ids: Vec<_> = record.expected.iter().filter_map(|t| crate::terminals::parse_id(&t.address)).collect();
        self.acknowledge_close(&operation, &ids)?;
        self.flush_close_saved().await?;
        Ok(json!({"ok":true,"operation_id":operation,"terminated":record.expected}))
    }

    pub(crate) fn close_snapshot(&self, roots: &[String]) -> Result<Value, RpcError> {
        let st = self.lock();
        let mut all = targets(&st)?;
        for witness in st.reg.close_witnesses.values() {
            if !all.iter().any(|t| t.identity.address == witness.target.identity.address) {
                all.push(witness.target.clone());
            }
        }
        let selected = plan::closure(roots, &all).map_err(denied)?;
        let expected: Vec<_> = selected.iter().map(|t| t.identity.clone()).collect();
        let snapshots: Vec<_> = selected
            .iter()
            .map(|t| {
                let id = crate::terminals::parse_id(&t.identity.address).unwrap();
                let live = st.reg.terminals.get(&id).is_some_and(|t| t.is_live());
                let observed = st
                    .reg
                    .close_witnesses
                    .get(&t.identity.address)
                    .is_some_and(|w| w.target.identity == t.identity && (w.code.is_some() || w.signal.is_some()));
                json!({"address":t.identity.address,"pid":t.identity.pid,"created_ms":t.identity.created_ms,
                "input_generation":t.input_generation,"program_started_ms":t.program_started_ms,
                "turn":t.turn,"status":t.state,
                "native_state":if live {"live"} else {"finished"},"observed_exit":observed})
            })
            .collect();
        let operations: Vec<_> = st.reg.close_operations.iter().filter(|(_, op)| op.expected.iter().any(|t| expected.contains(t)))
            .map(|(id, op)| json!({"operation_id":id,"roots":op.roots,"expected":op.expected,"acknowledged":op.acknowledged,"signalled":op.signalled,"cancelled":op.cancelled})).collect();
        Ok(
            json!({"core_id":self.info.id,"roots":roots,"expected":expected,"targets":snapshots,"operations":operations}),
        )
    }
}
