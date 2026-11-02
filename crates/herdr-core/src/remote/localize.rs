//! Addresses as another core says them, and as they are seen here.

use crate::runtime::{Core, State};
use serde_json::Value;

/// Addresses from the core called `name`: its `t7` is `name/t7` here; ours
/// (by our id, our name, or an `alias` it calls us) are bare again.
pub fn localize(core: &Core, name: &str, aliases: &[&str], v: Value) -> Value {
    localize_in(core, &core.lock(), name, aliases, v)
}

pub(super) fn map_addresses(v: &mut Value, map: &dyn Fn(&str) -> String) {
    match v {
        Value::Object(o) => {
            for (k, v) in o.iter_mut() {
                match v {
                    Value::String(s)
                        if ["address", "parent", "terminal", "from", "removed", "source", "target"]
                            .contains(&k.as_str()) =>
                    {
                        *s = map(s)
                    }
                    _ => map_addresses(v, map),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|v| map_addresses(v, map)),
        _ => {}
    }
}

pub(super) fn localize_in(core: &Core, st: &State, name: &str, aliases: &[&str], mut v: Value) -> Value {
    let map = |s: &str| match s.split_once('/') {
        None => format!("{name}/{s}"),
        Some((prefix, rest)) if prefix == core.info.id || prefix == core.info.name || aliases.contains(&prefix) => {
            rest.to_string()
        }
        Some((prefix, rest)) => match st.machines.iter().find(|m| m.id == prefix) {
            Some(m) => format!("{}/{rest}", m.name),
            None => s.to_string(),
        },
    };
    map_addresses(&mut v, &map);
    v
}
