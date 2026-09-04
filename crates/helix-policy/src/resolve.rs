//! Host resolve pass: rules 2 and 5, intern, snapshot (ADR-008 A.3, C.2).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use helix_caps::{
    CapabilitySet, DirGrant, FileGrant, HostGrant, Identity, Interface, Interner, MethodMask,
    ResourceBudget, ToolDigest,
};

use crate::file::{GrantTable, PolicyFile};
use crate::fs::{Fs, PathKind};
use crate::ids::{
    parse_identity_thumbprint, parse_interface, parse_method, parse_mode, parse_tool_digest,
};
use crate::store::ArtifactStore;
use crate::validate::validate_structural;
use crate::PolicyError;

/// One interned grant: authority plus resource ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedGrant {
    identity: Identity,
    digest: ToolDigest,
    identity_alias: String,
    tool_alias: String,
    caps: CapabilitySet,
    budget: ResourceBudget,
}

impl ResolvedGrant {
    /// Resolved identity.
    #[must_use]
    pub fn identity(&self) -> Identity {
        self.identity
    }
    /// Resolved tool digest.
    #[must_use]
    pub fn digest(&self) -> ToolDigest {
        self.digest
    }
    /// Identity alias from the file.
    #[must_use]
    pub fn identity_alias(&self) -> &str {
        &self.identity_alias
    }
    /// Tool alias from the file.
    #[must_use]
    pub fn tool_alias(&self) -> &str {
        &self.tool_alias
    }
    /// Interned capability set.
    #[must_use]
    pub fn caps(&self) -> &CapabilitySet {
        &self.caps
    }
    /// Resource budget (`preempt_ticks` defaulted to `wall_clock_ms` when omitted).
    #[must_use]
    pub fn budget(&self) -> ResourceBudget {
        self.budget
    }
}

/// Immutable interned snapshot held behind [`crate::PolicyHolder`]'s `ArcSwap`.
#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    interner: Interner,
    grants: HashMap<(Identity, ToolDigest), ResolvedGrant>,
    identities: HashMap<String, Identity>,
    tools: HashMap<String, ToolDigest>,
    warnings: Vec<String>,
    /// Monotonic version stamped by [`crate::PolicyHolder`] on each successful swap.
    version: u64,
    /// Instant of the successful load/reload that produced this snapshot.
    loaded_at: std::time::Instant,
}

impl PolicySnapshot {
    /// Snapshot-scoped intern table (ADR-008 A.3).
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Direct `(identity, digest)` lookup. `None` is a miss (HLX-15 owns reload).
    #[must_use]
    pub fn grant(&self, identity: &Identity, digest: &ToolDigest) -> Option<&ResolvedGrant> {
        self.grants.get(&(*identity, *digest))
    }

    /// All resolved grants.
    pub fn grants(&self) -> impl Iterator<Item = &ResolvedGrant> {
        self.grants.values()
    }

    /// Identity alias map.
    #[must_use]
    pub fn identities(&self) -> &HashMap<String, Identity> {
        &self.identities
    }

    /// Tool alias map.
    #[must_use]
    pub fn tools(&self) -> &HashMap<String, ToolDigest> {
        &self.tools
    }

    /// Host-pass warnings (rule 6 reverse; identity cap vs runtime pool).
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// `policy_version` for `helix.health` (ADR-008 C.3 / policy-format §4).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// When this snapshot was swapped in.
    #[must_use]
    pub fn loaded_at(&self) -> std::time::Instant {
        self.loaded_at
    }

    /// Direct lookup returning caps and budget refs (policy-format §3).
    #[must_use]
    pub fn policy(
        &self,
        identity: &Identity,
        digest: &ToolDigest,
    ) -> Option<(&CapabilitySet, &ResourceBudget)> {
        self.grants
            .get(&(*identity, *digest))
            .map(|g| (&g.caps, &g.budget))
    }

    /// Resolve a tool alias against this snapshot's table.
    #[must_use]
    pub fn resolve_alias(&self, name: &str) -> Option<ToolDigest> {
        self.tools.get(name).copied()
    }

    /// Stamp `version` / `loaded_at` after a successful holder swap. Used by the holder.
    pub(crate) fn stamp(mut self, version: u64, loaded_at: std::time::Instant) -> Self {
        self.version = version;
        self.loaded_at = loaded_at;
        self
    }

    /// Test/helper: override `loaded_at` without reloading.
    #[must_use]
    pub fn with_loaded_at(mut self, loaded_at: std::time::Instant) -> Self {
        self.loaded_at = loaded_at;
        self
    }
}

/// Host resolve: rule 2 (digest exists), rule 5 (paths), intern, snapshot.
///
/// Also runs the structural pass and concatenates its errors. Logs at `warn`
/// when an identity's `max_concurrent_instances` exceeds
/// `runtime.max_concurrent_instances` (ADR-009 B.1).
///
/// # Errors
///
/// Every structural or host-rule violation. No snapshot is returned on failure.
pub fn resolve_host<S: ArtifactStore>(
    file: &PolicyFile,
    artifacts: &S,
    fs: &dyn Fs,
) -> Result<PolicySnapshot, Vec<PolicyError>> {
    let mut errors = Vec::new();
    if let Err(mut structural) = validate_structural(file) {
        errors.append(&mut structural);
    }
    check_artifacts(file, artifacts, &mut errors);
    check_grant_paths(file, fs, &mut errors);
    if errors.is_empty() {
        build_snapshot(file, artifacts, fs)
    } else {
        Err(errors)
    }
}

fn check_artifacts<S: ArtifactStore>(
    file: &PolicyFile,
    artifacts: &S,
    errors: &mut Vec<PolicyError>,
) {
    for (alias, digest_str) in &file.tools {
        if let Ok(digest) = parse_tool_digest(alias, digest_str) {
            if !artifacts.contains(&digest) {
                errors.push(PolicyError::MissingArtifact {
                    alias: alias.clone(),
                    digest: digest_str.clone(),
                });
            }
        }
    }
}

fn check_grant_paths(file: &PolicyFile, fs: &dyn Fs, errors: &mut Vec<PolicyError>) {
    for grant in &file.grants {
        for f in &grant.files {
            if let Err(e) = resolve_path(fs, Path::new(&f.path), PathKind::File) {
                errors.push(e);
            }
        }
        for d in &grant.dirs {
            if let Err(e) = resolve_path(fs, Path::new(&d.path), PathKind::Directory) {
                errors.push(e);
            }
        }
    }
}

fn resolve_path(fs: &dyn Fs, path: &Path, expected: PathKind) -> Result<PathBuf, PolicyError> {
    if !path.is_absolute() {
        return Err(PolicyError::PathNotAbsolute(path.to_path_buf()));
    }
    reject_symlink_components(fs, path)?;
    let canonical = fs
        .canonicalize(path)
        .map_err(|e| PolicyError::NotCanonical {
            path: path.to_path_buf(),
            reason: e.message,
        })?;
    let kind = fs
        .path_kind(&canonical)
        .map_err(|e| PolicyError::NotCanonical {
            path: path.to_path_buf(),
            reason: e.message,
        })?;
    if kind == PathKind::Symlink {
        return Err(PolicyError::Symlink(canonical));
    }
    match expected {
        PathKind::File if kind != PathKind::File => Err(PolicyError::NotFile(canonical)),
        PathKind::Directory if kind != PathKind::Directory => {
            Err(PolicyError::NotDirectory(canonical))
        }
        _ => Ok(canonical),
    }
}

fn reject_symlink_components(fs: &dyn Fs, path: &Path) -> Result<(), PolicyError> {
    if let Ok(PathKind::Symlink) = fs.path_kind(path) {
        return Err(PolicyError::Symlink(path.to_path_buf()));
    }
    let mut acc = PathBuf::new();
    for c in path.components() {
        acc.push(c);
        if let Ok(PathKind::Symlink) = fs.path_kind(&acc) {
            return Err(PolicyError::Symlink(acc));
        }
    }
    Ok(())
}

fn build_snapshot<S: ArtifactStore>(
    file: &PolicyFile,
    artifacts: &S,
    fs: &dyn Fs,
) -> Result<PolicySnapshot, Vec<PolicyError>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut interner = Interner::new();
    let identities = parse_identities(file, &mut errors);
    let tools = parse_tools(file, &mut errors);

    let mut grants = HashMap::new();
    for grant in &file.grants {
        match build_grant(file, grant, fs, &mut interner, &identities, &tools) {
            Ok(built) => {
                warnings.extend(built.warnings);
                grants.insert(built.key, built.resolved);
            }
            Err(mut e) => errors.append(&mut e),
        }
    }

    for g in grants.values_mut() {
        g.caps = g.caps.clone().with_interner(interner.clone());
    }
    warn_identity_caps(&grants, artifacts, &mut warnings);

    if errors.is_empty() {
        Ok(PolicySnapshot {
            interner,
            grants,
            identities,
            tools,
            warnings,
            version: 0,
            loaded_at: std::time::Instant::now(),
        })
    } else {
        Err(errors)
    }
}

fn parse_identities(file: &PolicyFile, errors: &mut Vec<PolicyError>) -> HashMap<String, Identity> {
    let mut identities = HashMap::new();
    for (name, thumb) in &file.identities {
        match parse_identity_thumbprint(name, thumb) {
            Ok(id) => {
                identities.insert(name.clone(), id);
            }
            Err(e) => errors.push(e),
        }
    }
    identities
}

fn parse_tools(file: &PolicyFile, errors: &mut Vec<PolicyError>) -> HashMap<String, ToolDigest> {
    let mut tools = HashMap::new();
    for (alias, digest_str) in &file.tools {
        match parse_tool_digest(alias, digest_str) {
            Ok(d) => {
                tools.insert(alias.clone(), d);
            }
            Err(e) => errors.push(e),
        }
    }
    tools
}

fn warn_identity_caps<S: ArtifactStore>(
    grants: &HashMap<(Identity, ToolDigest), ResolvedGrant>,
    artifacts: &S,
    warnings: &mut Vec<String>,
) {
    let Some(pool) = artifacts.runtime_max_concurrent_instances() else {
        return;
    };
    let mut by_identity: HashMap<String, u32> = HashMap::new();
    for g in grants.values() {
        let cap = g.budget.max_concurrent_instances();
        by_identity
            .entry(g.identity_alias.clone())
            .and_modify(|m| *m = (*m).max(cap))
            .or_insert(cap);
    }
    for (alias, cap) in by_identity {
        if cap > pool {
            let msg = format!(
                "identity {alias} max_concurrent_instances {cap} exceeds runtime.max_concurrent_instances {pool}"
            );
            log::warn!("{msg}");
            warnings.push(msg);
        }
    }
}

struct BuiltGrant {
    key: (Identity, ToolDigest),
    resolved: ResolvedGrant,
    warnings: Vec<String>,
}

fn build_grant(
    file: &PolicyFile,
    grant: &GrantTable,
    fs: &dyn Fs,
    interner: &mut Interner,
    identities: &HashMap<String, Identity>,
    tools: &HashMap<String, ToolDigest>,
) -> Result<BuiltGrant, Vec<PolicyError>> {
    let mut errors = Vec::new();
    let identity = lookup_identity(grant, identities, &mut errors);
    let digest = lookup_digest(grant, tools, &mut errors);
    let Some(budget) = budget_for(file, grant, &mut errors) else {
        return Err(errors);
    };
    let (Some(identity), Some(digest)) = (identity, digest) else {
        return Err(errors);
    };

    let interfaces = parse_interfaces(grant, &mut errors);
    let warnings = interface_gap_warnings(grant, &interfaces);
    let files = intern_files(grant, fs, interner, &mut errors);
    let dirs = intern_dirs(grant, fs, interner, &mut errors);
    let hosts = intern_hosts(grant, interner, &mut errors);
    if !errors.is_empty() {
        return Err(errors);
    }

    let caps = CapabilitySet::new(&interfaces, files, dirs, hosts)
        .map_err(|e| vec![PolicyError::Caps(e.to_string())])?
        .with_interner(interner.clone());

    Ok(BuiltGrant {
        key: (identity, digest),
        resolved: ResolvedGrant {
            identity,
            digest,
            identity_alias: grant.identity.clone(),
            tool_alias: grant.tool.clone(),
            caps,
            budget,
        },
        warnings,
    })
}

fn lookup_identity(
    grant: &GrantTable,
    identities: &HashMap<String, Identity>,
    errors: &mut Vec<PolicyError>,
) -> Option<Identity> {
    identities.get(&grant.identity).copied().or_else(|| {
        errors.push(PolicyError::UnknownIdentity {
            identity: grant.identity.clone(),
        });
        None
    })
}

fn lookup_digest(
    grant: &GrantTable,
    tools: &HashMap<String, ToolDigest>,
    errors: &mut Vec<PolicyError>,
) -> Option<ToolDigest> {
    tools.get(&grant.tool).copied().or_else(|| {
        errors.push(PolicyError::UnknownTool {
            tool: grant.tool.clone(),
        });
        None
    })
}

fn budget_for(
    file: &PolicyFile,
    grant: &GrantTable,
    errors: &mut Vec<PolicyError>,
) -> Option<ResourceBudget> {
    let Some(budget_table) = file.budgets.get(&grant.budget) else {
        errors.push(PolicyError::UnknownBudget {
            name: grant.budget.clone(),
        });
        return None;
    };
    let preempt = budget_table
        .preempt_ticks
        .unwrap_or(budget_table.wall_clock_ms);
    Some(ResourceBudget::new(
        preempt,
        budget_table.wall_clock_ms,
        budget_table.memory_bytes,
        budget_table.output_bytes,
        budget_table.max_delegation_depth,
        budget_table.max_children,
        budget_table.max_concurrent_instances,
    ))
}

fn parse_interfaces(grant: &GrantTable, errors: &mut Vec<PolicyError>) -> Vec<Interface> {
    let mut interfaces = Vec::new();
    for name in &grant.interfaces {
        match parse_interface(name) {
            Ok(i) => interfaces.push(i),
            Err(e) => errors.push(e),
        }
    }
    interfaces
}

fn interface_gap_warnings(grant: &GrantTable, interfaces: &[Interface]) -> Vec<String> {
    let mut warnings = Vec::new();
    if interfaces.contains(&Interface::Filesystem)
        && grant.files.is_empty()
        && grant.dirs.is_empty()
    {
        let msg = format!(
            "grant {}/{} links filesystem with no files or dirs",
            grant.identity, grant.tool
        );
        log::warn!("{msg}");
        warnings.push(msg);
    }
    if interfaces.contains(&Interface::HttpOutbound) && grant.hosts.is_empty() {
        let msg = format!(
            "grant {}/{} links http_outbound with no hosts",
            grant.identity, grant.tool
        );
        log::warn!("{msg}");
        warnings.push(msg);
    }
    warnings
}

fn intern_files(
    grant: &GrantTable,
    fs: &dyn Fs,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
) -> Vec<FileGrant> {
    let mut files = Vec::new();
    for f in &grant.files {
        intern_one_file(f, fs, interner, errors, &mut files);
    }
    files
}

fn intern_dirs(
    grant: &GrantTable,
    fs: &dyn Fs,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
) -> Vec<DirGrant> {
    let mut dirs = Vec::new();
    for d in &grant.dirs {
        intern_one_dir(d, fs, interner, errors, &mut dirs);
    }
    dirs
}

fn intern_hosts(
    grant: &GrantTable,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
) -> Vec<HostGrant> {
    let mut hosts = Vec::new();
    for h in &grant.hosts {
        let mut methods = Vec::new();
        for m in &h.methods {
            match parse_method(m) {
                Ok(mm) => methods.push(mm),
                Err(e) => errors.push(e),
            }
        }
        let aid = interner.intern_authority(&h.authority);
        hosts.push(HostGrant::new(aid, MethodMask::new(&methods)));
    }
    hosts
}

fn intern_one_file(
    f: &crate::file::FileGrantTable,
    fs: &dyn Fs,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
    files: &mut Vec<FileGrant>,
) {
    push_file_grant(
        resolve_path(fs, Path::new(&f.path), PathKind::File),
        parse_mode(&f.mode),
        interner,
        errors,
        files,
    );
}

fn intern_one_dir(
    d: &crate::file::DirGrantTable,
    fs: &dyn Fs,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
    dirs: &mut Vec<DirGrant>,
) {
    push_dir_grant(
        resolve_path(fs, Path::new(&d.path), PathKind::Directory),
        parse_mode(&d.mode),
        interner,
        errors,
        dirs,
    );
}

fn push_file_grant(
    path: Result<PathBuf, PolicyError>,
    mode: Result<helix_caps::FileMode, PolicyError>,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
    files: &mut Vec<FileGrant>,
) {
    match path {
        Err(e) => errors.push(e),
        Ok(canon) => match mode {
            Ok(mode) => files.push(FileGrant::new(interner.intern_path(&canon), mode)),
            Err(e) => errors.push(e),
        },
    }
}

fn push_dir_grant(
    path: Result<PathBuf, PolicyError>,
    mode: Result<helix_caps::FileMode, PolicyError>,
    interner: &mut Interner,
    errors: &mut Vec<PolicyError>,
    dirs: &mut Vec<DirGrant>,
) {
    match path {
        Err(e) => errors.push(e),
        Ok(canon) => match mode {
            Ok(mode) => dirs.push(DirGrant::new(interner.intern_path(&canon), mode)),
            Err(e) => errors.push(e),
        },
    }
}
