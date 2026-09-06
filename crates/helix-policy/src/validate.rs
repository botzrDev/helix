//! Structural pass: rules 1, 3, 4, 6, 7, 8, 9, 10, 11, 12. No I/O.

use std::collections::HashSet;

use crate::file::{GrantTable, PolicyFile};
use crate::fs::Fs;
use crate::ids::{
    authority_is_valid, method_is_valid, parse_identity_thumbprint, parse_interface, parse_mode,
    parse_tool_digest,
};
use crate::PolicyError;

/// Structural validation. Never performs I/O.
///
/// # Errors
///
/// One [`PolicyError`] per violated structural rule (and malformed
/// identity/digest/interface/mode). Does not fail-fast.
pub fn validate_structural(file: &PolicyFile) -> Result<(), Vec<PolicyError>> {
    structural(file)
}

/// Same as [`validate_structural`]. `fs` is accepted so POL-7 can inject a
/// mock that panics on any call; this function never invokes `fs`.
///
/// # Errors
///
/// Same as [`validate_structural`].
pub fn validate_structural_with_fs(file: &PolicyFile, fs: &dyn Fs) -> Result<(), Vec<PolicyError>> {
    let _ = fs;
    structural(file)
}

fn structural(file: &PolicyFile) -> Result<(), Vec<PolicyError>> {
    let mut errors = Vec::new();
    if file.version != 1 {
        errors.push(PolicyError::Version { got: file.version });
    }
    check_tables(file, &mut errors);
    check_grants(file, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_tables(file: &PolicyFile, errors: &mut Vec<PolicyError>) {
    for (alias, digest) in &file.tools {
        if let Err(e) = parse_tool_digest(alias, digest) {
            errors.push(e);
        }
    }
    for (name, thumb) in &file.identities {
        if let Err(e) = parse_identity_thumbprint(name, thumb) {
            errors.push(e);
        }
    }
    for (name, budget) in &file.budgets {
        if let Some(preempt) = budget.preempt_ticks {
            if preempt > budget.wall_clock_ms {
                errors.push(PolicyError::PreemptTicks {
                    budget: name.clone(),
                    preempt,
                    wall: budget.wall_clock_ms,
                });
            }
        }
        if budget.max_concurrent_instances < 1 {
            errors.push(PolicyError::ConcurrentInstances {
                budget: name.clone(),
            });
        }
    }
}

fn check_grants(file: &PolicyFile, errors: &mut Vec<PolicyError>) {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for grant in &file.grants {
        check_grant(file, grant, &mut seen, errors);
    }
}

fn check_grant(
    file: &PolicyFile,
    grant: &GrantTable,
    seen: &mut HashSet<(String, String)>,
    errors: &mut Vec<PolicyError>,
) {
    if !file.identities.contains_key(&grant.identity) {
        errors.push(PolicyError::UnknownIdentity {
            identity: grant.identity.clone(),
        });
    }
    if !file.tools.contains_key(&grant.tool) {
        errors.push(PolicyError::UnknownTool {
            tool: grant.tool.clone(),
        });
    }
    if !seen.insert((grant.identity.clone(), grant.tool.clone())) {
        errors.push(PolicyError::DuplicateGrant {
            identity: grant.identity.clone(),
            tool: grant.tool.clone(),
        });
    }
    if !file.budgets.contains_key(&grant.budget) {
        errors.push(PolicyError::UnknownBudget {
            name: grant.budget.clone(),
        });
    }
    check_grant_digest(file, grant, errors);
    check_grant_interfaces(grant, errors);
    check_grant_paths_hosts(grant, errors);
}

fn check_grant_digest(file: &PolicyFile, grant: &GrantTable, errors: &mut Vec<PolicyError>) {
    match grant.digest.as_deref() {
        None => errors.push(PolicyError::MissingGrantDigest {
            tool: grant.tool.clone(),
        }),
        Some(d) => {
            if let Some(alias_digest) = file.tools.get(&grant.tool) {
                if d != alias_digest {
                    errors.push(PolicyError::DigestMismatch {
                        alias: grant.tool.clone(),
                        grant: d.to_owned(),
                        alias_digest: alias_digest.clone(),
                    });
                }
            }
        }
    }
}

fn check_grant_interfaces(grant: &GrantTable, errors: &mut Vec<PolicyError>) {
    let has_fs = grant.interfaces.iter().any(|i| i == "filesystem");
    let has_http = grant.interfaces.iter().any(|i| i == "http_outbound");
    if (!grant.files.is_empty() || !grant.dirs.is_empty()) && !has_fs {
        errors.push(PolicyError::FilesystemRequired {
            identity: grant.identity.clone(),
            tool: grant.tool.clone(),
        });
    }
    if !grant.hosts.is_empty() && !has_http {
        errors.push(PolicyError::HttpOutboundRequired {
            identity: grant.identity.clone(),
            tool: grant.tool.clone(),
        });
    }
    for iface in &grant.interfaces {
        if let Err(e) = parse_interface(iface) {
            errors.push(e);
        }
    }
}

fn check_grant_paths_hosts(grant: &GrantTable, errors: &mut Vec<PolicyError>) {
    for f in &grant.files {
        if let Err(e) = parse_mode(&f.mode) {
            errors.push(e);
        }
    }
    for d in &grant.dirs {
        if let Err(e) = parse_mode(&d.mode) {
            errors.push(e);
        }
    }
    for host in &grant.hosts {
        if !authority_is_valid(&host.authority) {
            errors.push(PolicyError::Authority(host.authority.clone()));
        }
        for m in &host.methods {
            if !method_is_valid(m) {
                errors.push(PolicyError::UnknownMethod(m.clone()));
            }
        }
    }
}
