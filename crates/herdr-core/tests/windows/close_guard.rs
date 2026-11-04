//! Real disposable ConPTY programs through the production dispatcher and pipes.
use super::*;
use serde_json::json;

fn guarded(mode: &str) -> Session {
    let s = Session::new();
    let folder = s.root.join("config/herdr-core");
    std::fs::create_dir_all(&folder).unwrap();
    let argv = json!([
        "py",
        "-3.12",
        format!("{}/tests/fixtures/close_authorizer.py", env!("CARGO_MANIFEST_DIR")),
        mode,
        s.root
    ]);
    std::fs::write(folder.join("config.toml"), format!("close_guard = {argv}\n")).unwrap();
    s
}

fn rpc(s: &Session, method: &str, params: Value) -> Result<Value, herdr_core::rpc::RpcError> {
    let (_, prefix) = herdr_core::platform::endpoints(&s.root);
    let socket = PathBuf::from(format!(r"\\.\pipe\{prefix}{}.sock", s.name));
    let pipe = herdr_core::platform::connect(&socket).unwrap();
    herdr_core::client::call(&pipe, method, params)
}

#[test]
fn native_close_denial_preserves_a_live_shell_and_returns_only_a_no_signal_certificate() {
    let s = guarded("denied");
    let t = s.bg(&["powershell", "-NoProfile", "-Command", "Write-Host ready; Start-Sleep 4"]);
    s.shows(&t, "ready");
    let snapshot = rpc(&s, "terminal.close_snapshot", json!({"roots":[t]})).unwrap();
    let plan = json!({"operation_id":"native-denial", "roots":[t], "expected":snapshot["expected"]});
    assert!(rpc(&s, "terminal.kill_batch", plan.clone()).is_err());
    assert_eq!(s.json(&["get", &t])["state"], "live");
    assert_ne!(s.out(&["kill", &t]).0, 0, "direct CLI kill must use the same guard");
    let proof = rpc(&s, "terminal.close_reconcile", plan).unwrap();
    assert_eq!(proof["no_signal"], true);
    assert_eq!(proof["expected"], snapshot["expected"]);
    assert!(proof.get("terminated").is_none());
    wait_until("disposable shell naturally finished", || s.json(&["get", &t])["state"] == "finished");
}

#[test]
fn native_actual_exit_and_lost_ack_reconcile_return_the_original_exact_receipt() {
    let s = guarded("bad_ack");
    let t = s.bg(&["powershell", "-NoProfile", "-Command", "Write-Host ready; Start-Sleep 30"]);
    s.shows(&t, "ready");
    let snapshot = rpc(&s, "terminal.close_snapshot", json!({"roots":[t]})).unwrap();
    let plan = json!({"operation_id":"native-lost-ack", "roots":[t], "expected":snapshot["expected"]});
    assert!(rpc(&s, "terminal.kill_batch", plan.clone()).is_err());
    assert_eq!(s.json(&["get", &t])["state"], "finished");
    assert_ne!(s.out(&["rm", &t]).0, 0, "rm must preserve evidence before ACK");
    let receipt = rpc(&s, "terminal.close_reconcile", plan).unwrap();
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["operation_id"], "native-lost-ack");
    assert_eq!(receipt["terminated"], snapshot["expected"]);
    let request: Value = serde_json::from_slice(&std::fs::read(s.root.join("request.json")).unwrap()).unwrap();
    assert_eq!(request["targets"][0]["observed_exit"], true);
    assert_eq!(request["core_id"], snapshot["core_id"]);
    assert_eq!(s.out(&["rm", &t]).0, 0);
}
