//! Authorized termination and server handover.
use super::*;

impl Core {
    /// Hang up, then escalate. Returns once the program ended or KILL timed out.
    pub async fn kill(&self, ids: &[u32]) -> Result<(), crate::rpc::RpcError> {
        if ids.is_empty() {
            return Ok(());
        }
        if self.close_guard.is_some() {
            self.guarded_close(
                ids.iter().map(|id| crate::terminals::address(*id)).collect(),
                None,
                serde_json::Value::Null,
            )
            .await?;
        } else {
            if !self.lock().stopping {
                self.lock().killing.extend(ids);
            }
            self.kill_authorized(ids).await;
        }
        Ok(())
    }

    pub(crate) async fn kill_authorized(&self, ids: &[u32]) {
        let all_done = |st: &State| {
            ids.iter().all(|id| !st.reg.terminals.get(id).is_some_and(|t| t.is_live() && t.holder.is_some()))
        };
        {
            let mut st = self.lock();
            for &id in ids {
                if st
                    .reg
                    .terminals
                    .get(&id)
                    .is_some_and(|t| t.is_live() && (t.holder.is_none() || (t.reason.is_some() && t.pid.is_none())))
                {
                    let reason = if st.killing.contains(&id) { "killed" } else { "server_stop" };
                    if let Some(link) = st.link(id) {
                        link.send(&proto::json_frame(proto::SIGNAL, id, &proto::Signal { signal: signal::KILL }));
                        link.send(&proto::frame(proto::RELEASE, id, &[]));
                    }
                    self.record_finish(&mut st, id, Exit { code: None, signal: None }, reason);
                }
            }
            self.save(&st);
        }
        for (signal, wait) in [(signal::HUP, 500), (signal::TERM, 500), (signal::KILL, 2000)] {
            {
                let st = self.lock();
                for &id in ids {
                    self.signal(&st, id, signal);
                }
            }
            if self.wait_for(Duration::from_millis(wait), all_done).await {
                return;
            }
        }
    }

    /// Ends every link on purpose and waits until each holder confirms.
    fn goodbye(&self, mode: Goodbye) {
        let _starting = self.holder_start.lock().unwrap_or_else(|p| p.into_inner());
        let byes: Vec<mpsc::Receiver<()>> = {
            let mut st = self.lock();
            st.holders
                .iter_mut()
                .filter_map(|link| {
                    link.send(&proto::json_frame(proto::GOODBYE, 0, &mode));
                    link.bye_rx.take()
                })
                .collect()
        };
        if mode == Goodbye::Shutdown {
            let sockets: Vec<_> = self.lock().disconnected.drain().map(|(_, path)| path).collect();
            for path in sockets {
                if let Ok(mut stream) = platform::connect(&path) {
                    let Ok(watch) = stream.try_clone() else { continue };
                    let (done, waiting) = mpsc::channel::<()>();
                    std::thread::spawn(move || {
                        if waiting.recv_timeout(Duration::from_secs(6)) == Err(mpsc::RecvTimeoutError::Timeout) {
                            let _ = watch.shutdown(std::net::Shutdown::Both);
                        }
                    });
                    // The welcome may be unreadable (the reason relink failed).
                    // Shutdown needs no inventory: the holder sweeps everything it owns.
                    let hello = proto::json_frame(proto::HELLO, 0, &proto::Hello { version: proto::VERSION });
                    if io::Write::write_all(&mut stream, &hello).is_ok()
                        && io::Write::write_all(&mut stream, &proto::json_frame(proto::GOODBYE, 0, &mode)).is_ok()
                    {
                        let _ = io::copy(&mut stream, &mut io::sink());
                    }
                    drop(done);
                }
            }
        }
        for rx in byes {
            // A holder told to shut down first ends every leftover (up to ~3 s).
            let _ = rx.recv_timeout(Duration::from_secs(6));
        }
    }

    /// Ends what lost terminals left running, in the background but counted:
    /// stop and restart wait for it.
    pub(super) fn sweep_in_background(&self, scopes: Vec<String>) {
        if scopes.is_empty() || self.close_guard.is_some() {
            return;
        }
        self.sweeps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let sweeps = self.sweeps.clone();
        std::thread::spawn(move || {
            crate::sweep::sweep(&scopes);
            sweeps.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }

    fn wait_for_sweeps(&self) {
        let deadline = Instant::now() + Duration::from_secs(6);
        while self.sweeps.load(std::sync::atomic::Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Planned restart: the holder keeps programs; we save every screen exactly.
    pub async fn handover(&self) -> io::Result<()> {
        self.wait_for_sweeps();
        self.goodbye(Goodbye::Handover);
        self.wait_for_sweeps(); // a holder that died during goodbye left one
        {
            let mut st = self.lock();
            st.holders.clear();
            let State { screens, relays, .. } = &mut *st;
            for (id, screen) in screens.iter_mut() {
                if let Some(relay) = relays.get_mut(id) {
                    relay.flush(screen);
                }
                if let Some(snapshot) = screen.snapshot() {
                    let _ = write_atomic(&self.snapshot_path(*id), &snapshot);
                }
            }
            self.save(&st);
        }
        self.registry_writer.flush().await
    }

    /// Server stop: end every program, then let the holder exit.
    pub async fn shutdown(&self) -> Result<(), crate::rpc::RpcError> {
        let live: Vec<u32> = {
            let mut st = self.lock();
            if self.close_guard.is_some()
                && (st.close_unverified_orphan || st.reg.terminals.values().any(|t| t.is_live()))
            {
                return Err(crate::close_guard::denied("close guarded batches before stopping the core"));
            }
            st.stopping = true;
            st.reg.terminals.values().filter(|t| t.is_live()).map(|t| t.id()).collect()
        };
        self.changed.notify_waiters(); // execs end
        self.kill(&live).await?;
        crate::exec::wait_all().await;
        self.wait_for_sweeps();
        self.goodbye(Goodbye::Shutdown);
        self.wait_for_sweeps(); // a holder that died during goodbye left one
        {
            let mut st = self.lock();
            for id in live {
                self.record_finish(&mut st, id, Exit { code: None, signal: None }, "server_stop");
            }
            self.save(&st);
        }
        self.flush_saved().await
    }
}
