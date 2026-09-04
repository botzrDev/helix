//! Lattice operations on [`CapabilitySet`] (HLX-11 / M1-02).
//!
//! Subset, meet, and attenuation follow ADR-008 A.2 (prefix `DirGrant`) and
//! A.3 (intern-id merge walk). [`crate::ResourceBudget`] is not a lattice
//! element; [`crate::Interner`] is snapshot infrastructure only.

use crate::{
    CapabilitySet, CapsError, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner, PathId,
};

const INTERFACES: [Interface; 5] = [
    Interface::Stdio,
    Interface::Clocks,
    Interface::Random,
    Interface::Filesystem,
    Interface::HttpOutbound,
];

impl CapabilitySet {
    /// True if `self` grants nothing that `other` does not.
    ///
    /// Complexity: O(|files| + |dirs| + |hosts|) with a merge walk that
    /// consults `dirs` for uncovered files (ADR-008 A.2). Pure. After
    /// intern, a merge of two sorted u32 slices (ADR-008 A.3).
    ///
    /// Definition:
    /// - `self.interfaces & !other.interfaces == 0`
    /// - every `FileGrant` in `self` is covered either by a `FileGrant` in
    ///   `other` with the same path id and `self.mode <= other.mode`, or by
    ///   a `DirGrant` in `other` whose root is an ancestor of the file path,
    ///   with the same mode rule
    /// - every `DirGrant` in `self` is covered by a `DirGrant` in `other`
    ///   whose root is an ancestor-or-equal path and whose mode is
    ///   greater-or-equal
    /// - every `HostGrant` in `self` has a match in `other` with the same
    ///   authority id and `self.methods` subset of `other.methods`
    ///
    /// Budget is not consulted.
    #[must_use]
    pub fn is_subset_of(&self, other: &CapabilitySet) -> bool {
        debug_assert!(self.invariants_hold());
        debug_assert!(other.invariants_hold());
        if self.interfaces_bits() & !other.interfaces_bits() != 0 {
            return false;
        }
        files_subset(self, other) && dirs_subset(self, other) && hosts_subset(self, other)
    }

    /// Returns `requested` if and only if `requested.is_subset_of(parent)`.
    /// This is the entire authority-side delegation policy. Pure.
    /// Resource composition is `ResourceBudget::is_within`, separately.
    ///
    /// # Errors
    ///
    /// Returns [`CapsError::Escalation`] when `requested` is not a subset of
    /// `parent`.
    pub fn attenuate(
        parent: &CapabilitySet,
        requested: &CapabilitySet,
    ) -> Result<CapabilitySet, CapsError> {
        debug_assert!(parent.invariants_hold());
        debug_assert!(requested.invariants_hold());
        if requested.is_subset_of(parent) {
            Ok(requested.clone())
        } else {
            Err(CapsError::Escalation(
                "requested set exceeds parent".to_owned(),
            ))
        }
    }

    /// Greatest lower bound. Used to compute the effective set when a policy
    /// grant and a delegation request both apply. Pure.
    ///
    /// Meet of two `DirGrant`s is the more specific root when one contains
    /// the other, and absent otherwise. Meet of a `FileGrant` with a covering
    /// `DirGrant` is the `FileGrant` with the lesser mode (ADR-008 A.2).
    #[must_use]
    pub fn meet(&self, other: &CapabilitySet) -> CapabilitySet {
        debug_assert!(self.invariants_hold());
        debug_assert!(other.invariants_hold());
        let bits = self.interfaces_bits() & other.interfaces_bits();
        let intern = merged_interner(self, other);
        let (files, dirs, hosts) = meet_grants(self, other, &intern, bits);
        finish(bits, files, dirs, hosts, intern)
    }
}

fn finish(
    bits: u64,
    files: Vec<FileGrant>,
    dirs: Vec<DirGrant>,
    hosts: Vec<HostGrant>,
    intern: Interner,
) -> CapabilitySet {
    let interfaces: Vec<Interface> = INTERFACES
        .into_iter()
        .filter(|i| bits & i.bit() != 0)
        .collect();
    match CapabilitySet::new(&interfaces, files, dirs, hosts) {
        Ok(set) => set.with_interner(intern),
        Err(_) => CapabilitySet::EMPTY,
    }
}

fn merged_interner(a: &CapabilitySet, b: &CapabilitySet) -> Interner {
    let mut intern = if a.interner().is_empty() {
        b.interner().clone()
    } else {
        a.interner().clone()
    };
    intern_grants_into(&mut intern, a);
    intern_grants_into(&mut intern, b);
    intern
}

fn intern_grants_into(intern: &mut Interner, set: &CapabilitySet) {
    if set.interner().is_empty() {
        return;
    }
    for f in set.files() {
        intern.intern_path(set.interner().path(f.path()));
    }
    for d in set.dirs() {
        intern.intern_path(set.interner().path(d.root()));
    }
    for h in set.hosts() {
        intern.intern_authority(set.interner().authority(h.authority()));
    }
}

fn remap_path(intern: &Interner, set: &CapabilitySet, id: PathId) -> PathId {
    if intern.is_empty() || set.interner().is_empty() {
        return id;
    }
    intern.get_path(set.interner().path(id)).unwrap_or(id)
}

fn remap_authority(
    intern: &Interner,
    set: &CapabilitySet,
    id: crate::AuthorityId,
) -> crate::AuthorityId {
    if intern.is_empty() || set.interner().is_empty() {
        return id;
    }
    intern
        .get_authority(set.interner().authority(id))
        .unwrap_or(id)
}

fn same_ids(a: &CapabilitySet, b: &CapabilitySet) -> bool {
    !a.interner().is_empty() && !b.interner().is_empty() && a.interner().same_snapshot(b.interner())
}

fn files_subset(this: &CapabilitySet, other: &CapabilitySet) -> bool {
    if same_ids(this, other) {
        files_subset_merge(this, other, this.interner())
    } else {
        this.files()
            .iter()
            .all(|f| file_covered_scan(this, *f, other))
    }
}

fn files_subset_merge(this: &CapabilitySet, other: &CapabilitySet, intern: &Interner) -> bool {
    let theirs = other.files();
    let mut j = 0usize;
    for f in this.files() {
        while j < theirs.len() && theirs[j].path() < f.path() {
            j += 1;
        }
        let exact =
            j < theirs.len() && theirs[j].path() == f.path() && f.mode() <= theirs[j].mode();
        if exact || dir_covers_id(intern, other.dirs(), f.path(), f.mode()) {
            continue;
        }
        return false;
    }
    true
}

fn file_covered_scan(this: &CapabilitySet, file: FileGrant, other: &CapabilitySet) -> bool {
    for of in other.files() {
        if path_eq(this, file.path(), other, of.path()) && file.mode() <= of.mode() {
            return true;
        }
    }
    for od in other.dirs() {
        if prefix_cross(other, od.root(), this, file.path()) && file.mode() <= od.mode() {
            return true;
        }
    }
    false
}

fn dirs_subset(this: &CapabilitySet, other: &CapabilitySet) -> bool {
    if same_ids(this, other) {
        this.dirs()
            .iter()
            .all(|d| dir_covers_id(this.interner(), other.dirs(), d.root(), d.mode()))
    } else {
        this.dirs().iter().all(|d| {
            other
                .dirs()
                .iter()
                .any(|od| prefix_cross(other, od.root(), this, d.root()) && d.mode() <= od.mode())
        })
    }
}

fn hosts_subset(this: &CapabilitySet, other: &CapabilitySet) -> bool {
    if same_ids(this, other) {
        let theirs = other.hosts();
        let mut j = 0usize;
        for h in this.hosts() {
            while j < theirs.len() && theirs[j].authority() < h.authority() {
                j += 1;
            }
            if j < theirs.len()
                && theirs[j].authority() == h.authority()
                && h.methods().is_subset_of(theirs[j].methods())
            {
                continue;
            }
            return false;
        }
        true
    } else {
        this.hosts().iter().all(|h| {
            other.hosts().iter().any(|oh| {
                auth_eq(this, h.authority(), other, oh.authority())
                    && h.methods().is_subset_of(oh.methods())
            })
        })
    }
}

/// Whether `dirs` contains an ancestor-or-equal of `descendant` with mode `>=`.
/// Uses parent-chain id comparison (ADR-008 A.3); `dirs` is sorted by root id.
fn dir_covers_id(intern: &Interner, dirs: &[DirGrant], descendant: PathId, mode: FileMode) -> bool {
    if grant_covers(dirs, descendant, mode) {
        return true;
    }
    for &anc in intern.parent_chain(descendant) {
        if grant_covers(dirs, anc, mode) {
            return true;
        }
    }
    false
}

fn grant_covers(dirs: &[DirGrant], root: PathId, mode: FileMode) -> bool {
    match dirs.binary_search_by(|d| d.root().cmp(&root)) {
        Ok(i) => mode <= dirs[i].mode(),
        Err(_) => false,
    }
}

fn path_eq(a: &CapabilitySet, pa: PathId, b: &CapabilitySet, pb: PathId) -> bool {
    if a.interner().is_empty() || b.interner().is_empty() {
        return pa == pb;
    }
    a.interner().path(pa) == b.interner().path(pb)
}

fn auth_eq(
    a: &CapabilitySet,
    pa: crate::AuthorityId,
    b: &CapabilitySet,
    pb: crate::AuthorityId,
) -> bool {
    if a.interner().is_empty() || b.interner().is_empty() {
        return pa == pb;
    }
    a.interner().authority(pa) == b.interner().authority(pb)
}

fn prefix_cross(
    anc_set: &CapabilitySet,
    anc: PathId,
    desc_set: &CapabilitySet,
    desc: PathId,
) -> bool {
    if anc_set.interner().is_empty() || desc_set.interner().is_empty() {
        return anc == desc;
    }
    if let Some(d) = anc_set.interner().get_path(desc_set.interner().path(desc)) {
        return anc_set.interner().is_prefix(anc, d);
    }
    if let Some(a) = desc_set.interner().get_path(anc_set.interner().path(anc)) {
        return desc_set.interner().is_prefix(a, desc);
    }
    anc_set.interner().path(anc) == std::path::Path::new("/")
}

fn meet_grants(
    a: &CapabilitySet,
    b: &CapabilitySet,
    intern: &Interner,
    bits: u64,
) -> (Vec<FileGrant>, Vec<DirGrant>, Vec<HostGrant>) {
    let has_fs = bits & Interface::Filesystem.bit() != 0;
    let has_http = bits & Interface::HttpOutbound.bit() != 0;
    let files = if has_fs {
        meet_files(a, b, intern)
    } else {
        Vec::new()
    };
    let dirs = if has_fs {
        meet_dirs(a, b, intern)
    } else {
        Vec::new()
    };
    let hosts = if has_http {
        meet_hosts(a, b, intern)
    } else {
        Vec::new()
    };
    (files, dirs, hosts)
}

fn covering_file_mode(set: &CapabilitySet, intern: &Interner, path: PathId) -> Option<FileMode> {
    let mut best: Option<FileMode> = None;
    for f in set.files() {
        if remap_path(intern, set, f.path()) == path {
            best = Some(max_mode(best, f.mode()));
        }
    }
    for d in set.dirs() {
        let root = remap_path(intern, set, d.root());
        if intern.is_empty() {
            if root == path {
                best = Some(max_mode(best, d.mode()));
            }
        } else if intern.is_prefix(root, path) {
            best = Some(max_mode(best, d.mode()));
        }
    }
    best
}

fn max_mode(cur: Option<FileMode>, m: FileMode) -> FileMode {
    match cur {
        Some(c) => c.max(m),
        None => m,
    }
}

fn meet_files(a: &CapabilitySet, b: &CapabilitySet, intern: &Interner) -> Vec<FileGrant> {
    let mut paths: Vec<PathId> = a
        .files()
        .iter()
        .map(|f| remap_path(intern, a, f.path()))
        .chain(b.files().iter().map(|f| remap_path(intern, b, f.path())))
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let mut out = Vec::new();
    for path in paths {
        let Some(ma) = covering_file_mode(a, intern, path) else {
            continue;
        };
        let Some(mb) = covering_file_mode(b, intern, path) else {
            continue;
        };
        out.push(FileGrant::new(path, ma.min(mb)));
    }
    out
}

fn meet_dirs(a: &CapabilitySet, b: &CapabilitySet, intern: &Interner) -> Vec<DirGrant> {
    let mut out: Vec<DirGrant> = Vec::new();
    for da in a.dirs() {
        let ra = remap_path(intern, a, da.root());
        for db in b.dirs() {
            let rb = remap_path(intern, b, db.root());
            let nested = if intern.is_empty() {
                ra == rb
            } else if intern.is_prefix(ra, rb) {
                true
            } else {
                intern.is_prefix(rb, ra)
            };
            if !nested {
                continue;
            }
            // More specific root when nested; equal roots (or empty intern) keep `ra`.
            let root = if intern.is_empty() || intern.is_prefix(rb, ra) || !intern.is_prefix(ra, rb)
            {
                ra
            } else {
                rb
            };
            out.push(DirGrant::new(root, da.mode().min(db.mode())));
        }
    }
    out.sort_unstable();
    dedup_dirs_keep_max(&mut out);
    out
}

fn dedup_dirs_keep_max(dirs: &mut Vec<DirGrant>) {
    if dirs.len() < 2 {
        return;
    }
    let mut w = 1usize;
    for r in 1..dirs.len() {
        if dirs[r].root() == dirs[w - 1].root() {
            if dirs[r].mode() > dirs[w - 1].mode() {
                dirs[w - 1] = dirs[r];
            }
        } else {
            dirs[w] = dirs[r];
            w += 1;
        }
    }
    dirs.truncate(w);
}

fn meet_hosts(a: &CapabilitySet, b: &CapabilitySet, intern: &Interner) -> Vec<HostGrant> {
    let mut out: Vec<HostGrant> = Vec::new();
    for ha in a.hosts() {
        let aa = remap_authority(intern, a, ha.authority());
        for hb in b.hosts() {
            let ab = remap_authority(intern, b, hb.authority());
            if aa != ab {
                continue;
            }
            let methods = ha.methods().intersection(hb.methods());
            if methods.bits() == 0 {
                continue;
            }
            out.push(HostGrant::new(aa, methods));
        }
    }
    out.sort_unstable();
    out.dedup_by(|x, y| x.authority() == y.authority());
    out
}
