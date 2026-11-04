//! Pure close planning: canonical local identities and an exact descendant set.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Identity {
    pub address: String,
    pub pid: u32,
    pub created_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub identity: Identity,
    pub parent: Option<String>,
    pub input_generation: u64,
    pub program_started_ms: u64,
    pub turn: u64,
    pub state: String,
    pub protected: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CloseOperation {
    pub roots: Vec<String>,
    pub expected: Vec<Identity>,
    pub targets: Vec<Target>,
    pub observed_exits: BTreeSet<String>,
    pub acknowledged: bool,
    pub signalled: bool,
    pub cancelled: bool,
    #[serde(default)]
    pub audit_only: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExitWitness {
    pub target: Target,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub finished_ms: u64,
}

fn local(address: &str) -> bool {
    crate::terminals::parse_id(address).is_some_and(|id| crate::terminals::address(id) == address)
}

pub fn closure(roots: &[String], all: &[Target]) -> Result<Vec<Target>, &'static str> {
    let by_address: BTreeMap<_, _> = all.iter().map(|t| (t.identity.address.clone(), t)).collect();
    if roots.is_empty() || by_address.len() != all.len() {
        return Err("empty or ambiguous close set");
    }
    let mut selected = BTreeSet::new();
    for root in roots {
        if !local(root) || !by_address.contains_key(root) || !selected.insert(root.clone()) {
            return Err("unknown, duplicate or unsupported root");
        }
    }
    loop {
        let mut changed = false;
        for target in all {
            if !target.protected && target.parent.as_ref().is_some_and(|p| selected.contains(p)) {
                changed |= selected.insert(target.identity.address.clone());
            }
        }
        if !changed {
            break;
        }
    }
    selected
        .into_iter()
        .map(|address| {
            let target = by_address[&address];
            if !local(&address)
                || target.identity.pid == 0
                || target.identity.created_ms == 0
                || target.program_started_ms == 0
            {
                Err("incomplete terminal identity")
            } else {
                Ok(target.clone())
            }
        })
        .collect()
}

pub fn plan(roots: &[String], expected: &[Identity], all: &[Target]) -> Result<Vec<Target>, &'static str> {
    let targets = closure(roots, all)?;
    let expected_set: BTreeSet<_> = expected.iter().cloned().collect();
    let actual: BTreeSet<_> = targets.iter().map(|t| t.identity.clone()).collect();
    if expected_set.len() != expected.len() || expected_set != actual {
        return Err("expected identities do not equal the full live descendant closure");
    }
    Ok(targets)
}

pub fn revalidate(
    roots: &[String],
    expected: &[Identity],
    before: &[Target],
    after: &[Target],
) -> Result<(), &'static str> {
    if plan(roots, expected, after)? != before {
        return Err("close snapshot changed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: u32, parent: Option<u32>) -> Target {
        Target {
            identity: Identity { address: format!("t{id}"), pid: id + 100, created_ms: 1000 + u64::from(id) },
            parent: parent.map(|id| format!("t{id}")),
            input_generation: 0,
            program_started_ms: 2000,
            turn: 1,
            state: "done".into(),
            protected: false,
        }
    }

    #[test]
    fn batch_requires_every_descendant_and_exact_identity() {
        let all = vec![target(1, None), target(2, Some(1)), target(3, Some(2)), target(4, None)];
        let roots = vec!["t1".into()];
        let expected: Vec<_> = all[..3].iter().map(|t| t.identity.clone()).collect();
        assert_eq!(plan(&roots, &expected, &all).unwrap(), all[..3]);
        assert!(plan(&roots, &expected[..2], &all).is_err());
        let mut reused_pid = expected.clone();
        reused_pid[1].created_ms += 1;
        assert!(plan(&roots, &reused_pid, &all).is_err());
        let mut new_child = all;
        new_child.push(target(5, Some(3)));
        assert!(plan(&roots, &expected, &new_child).is_err());
    }

    #[test]
    fn base36_addresses_and_kept_pane_subtrees_preserve_existing_scope() {
        let root = target(1, None);
        let mut pane = target(2, Some(1));
        pane.protected = true;
        let grandchild = target(3, Some(2));
        let mut ordinary = target(4, Some(1));
        ordinary.identity.address = "t1s".into();
        let all = vec![root.clone(), pane.clone(), grandchild, ordinary.clone()];
        assert_eq!(closure(&["t1".into()], &all).unwrap(), vec![root.clone(), ordinary]);
        assert_eq!(closure(&["t2".into()], &all).unwrap().len(), 2);
        assert!(plan(&["t1".into()], &[root.identity, pane.identity], &all).is_err());
    }

    #[test]
    fn unknown_remote_duplicate_and_empty_requests_fail_closed() {
        let all = vec![target(1, None)];
        let expected = vec![all[0].identity.clone()];
        for roots in
            [vec![], vec!["worker/t1".into()], vec!["t01".into()], vec!["t9".into()], vec!["t1".into(), "t1".into()]]
        {
            assert!(plan(&roots, &expected, &all).is_err());
        }
        assert!(plan(&["t1".into()], &[expected[0].clone(), expected[0].clone()], &all).is_err());
    }

    #[test]
    fn revalidation_observes_input_program_and_state_changes() {
        let before = vec![target(1, None)];
        for change in 0..4 {
            let mut after = before.clone();
            match change {
                0 => after[0].input_generation += 1,
                1 => after[0].program_started_ms += 1,
                2 => after[0].turn += 1,
                _ => after[0].state = "working".into(),
            }
            assert!(revalidate(&["t1".into()], &[before[0].identity.clone()], &before, &after).is_err());
        }
    }
}
