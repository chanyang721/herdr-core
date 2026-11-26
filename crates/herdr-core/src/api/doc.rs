use super::*;
use crate::paths::write_atomic;

pub(super) async fn doc_get(core: Ctx<'_>, p: DocGetParams) -> Result<DocGetResult, RpcError> {
    crate::addr::check_name(&p.name)?;
    Ok(core.lock().docs.get(&p.name).cloned().unwrap_or_default())
}

pub(super) async fn doc_set(core: Ctx<'_>, p: DocSetParams) -> Result<DocSetResult, RpcError> {
    crate::addr::check_name(&p.name)?;
    if serde_json::to_vec(&p.value).map_err(|e| RpcError::invalid_params(e.to_string()))?.len() > 1024 * 1024 {
        return Err(RpcError::invalid_params("document exceeds 1 MiB of JSON"));
    }
    let mut st = core.lock();
    let current = st.docs.get(&p.name).map_or(0, |d| d.version);
    if p.version != current {
        return Err(RpcError::new(
            "conflict",
            format!("document {:?} is at version {current}, not {}", p.name, p.version),
            "read doc.get and retry with its version",
        ));
    }
    let version = current.checked_add(1).ok_or_else(|| RpcError::internal("document version exhausted"))?;
    let previous = st.docs.insert(p.name.clone(), DocGetResult { value: p.value, version });
    let bytes = serde_json::to_vec(&st.docs).expect("documents serialize");
    if let Err(e) = write_atomic(&core.paths.state.join("docs.json"), &bytes) {
        match previous {
            Some(doc) => {
                st.docs.insert(p.name, doc);
            }
            None => {
                st.docs.remove(&p.name);
            }
        }
        return Err(RpcError::internal(format!("cannot save document: {e}")));
    }
    core.doc_event(&mut st, json!({"name": p.name, "version": version}), None);
    st.policy_generation = st.policy_generation.wrapping_add(1);
    Ok(DocSetResult { version })
}
