//! Native-payload sandbox — running an unmanaged ELF binary the way wasm is
//! run under wasmtime: deny-by-default, with only what the manifest grants.
//!
//! WASM gives us a portable, structurally-deterministic sandbox for free.
//! Native payloads (a static musl `ferric-serve`, say) trade that portability
//! for raw speed and give up the interpreter's guarantees — so the OS must
//! supply the confinement instead. On Linux this is:
//!
//!   • **landlock** — filesystem access restricted to the payload's own
//!     directory (read+execute), a fresh per-run scratch (read+write), the
//!     standard runtime dirs (read, for dynamic binaries), and any `fs:<dir>`
//!     the manifest grants. Network (TCP bind/connect) is denied unless "net"
//!     is granted. Nothing else on the filesystem exists to the payload.
//!   • **seccomp** — a deny-list BPF filter (default allow) blocking the
//!     privilege-escalation / container-escape / kernel-tampering syscalls no
//!     compute payload needs (ptrace, kexec, module load, mount, bpf, setns,
//!     keyctl, …); matched calls return EPERM, so benign compute is untouched.
//!   • **no-new-privileges** — setuid/setgid/caps can never be gained.
//!   • **rlimits** — CPU seconds, address space, file size, fd count.
//!   • **cleared environment + scratch cwd**.
//!
//! The landlock ruleset is BUILT in the parent (where allocation is safe) and
//! only `restrict_self()` — a single syscall — runs in the post-fork child,
//! avoiding the malloc-after-fork hazard in the multi-threaded agent.
//!
//! Honest scope: unlike wasm, native execution is NOT made deterministic by
//! this sandbox — a native payload that reads the clock or RNG can vary, so
//! its eval vectors verify behavior only to the extent the binary is itself
//! deterministic. Off Linux the whole path returns an error. The seccomp
//! layer is a curated deny-list (safe against benign compute); a per-payload
//! allow-list profile signed into the manifest is a possible future tier.

use crate::{Output, RuntimeError};
use ferrite_pack::Requires;

/// Default CPU-seconds ceiling for one native eval/run.
pub const DEFAULT_CPU_SECS: u64 = 30;

#[cfg(all(target_os = "linux", feature = "native"))]
pub fn run_native(
    bytes: &[u8],
    input: &[u8],
    grants: &Requires,
    cpu_secs: u64,
) -> Result<Output, RuntimeError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let dir = tempfile::Builder::new()
        .prefix("ferrite-native-")
        .tempdir()
        .map_err(|e| RuntimeError::Host(format!("scratch: {e}")))?;
    let exe = dir.path().join("payload");
    std::fs::write(&exe, bytes).map_err(|e| RuntimeError::Host(format!("write payload: {e}")))?;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| RuntimeError::Host(format!("chmod: {e}")))?;
    let scratch = dir.path().join("scratch");
    std::fs::create_dir_all(&scratch).map_err(|e| RuntimeError::Host(format!("scratch dir: {e}")))?;

    // Build the landlock ruleset AND compile the seccomp BPF here, in the
    // parent — this is where allocation happens. The child only issues the
    // two install syscalls (restrict_self + seccomp), no allocation.
    let ruleset = build_ruleset(dir.path(), &scratch, grants)
        .map_err(|e| RuntimeError::Host(format!("landlock: {e}")))?;
    let bpf = build_seccomp().map_err(|e| RuntimeError::Host(format!("seccomp: {e}")))?;

    let mut cmd = Command::new(&exe);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .current_dir(&scratch);
    // pre_exec's closure is FnMut (may be called more than once in principle);
    // restrict_self() consumes the ruleset, so hold it in an Option and take().
    let mut ruleset = Some(ruleset);
    unsafe {
        cmd.pre_exec(move || {
            // no new privileges (prerequisite for both landlock and seccomp)
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            set_rlimit(libc::RLIMIT_CPU, cpu_secs);
            set_rlimit(libc::RLIMIT_FSIZE, 256 << 20);
            set_rlimit(libc::RLIMIT_AS, 4u64 << 30);
            set_rlimit(libc::RLIMIT_NOFILE, 64);
            // seccomp BEFORE landlock: landlock's restrict_self installs its
            // own LSM hook, and applying the seccomp filter afterward did not
            // take effect (observed: blocked syscalls still succeeded). Order
            // is irrelevant to what each enforces, so install the syscall
            // filter first, then the filesystem/network restriction.
            seccompiler::apply_filter(&bpf).map_err(std::io::Error::other)?;
            if let Some(r) = ruleset.take() {
                r.restrict_self_in_child().map_err(std::io::Error::other)?;
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| RuntimeError::Host(format!("spawn: {e}")))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .map_err(|e| RuntimeError::Host(format!("stdin: {e}")))?;
    // stdin dropped here → EOF for the payload. wait_with_output drains both
    // stdout and stderr concurrently, so a full stderr pipe can't deadlock us.
    let out = child
        .wait_with_output()
        .map_err(|e| RuntimeError::Host(format!("wait: {e}")))?;
    if !out.status.success() {
        return Err(RuntimeError::Exit(out.status.code().unwrap_or(-1)));
    }
    Ok(Output {
        stdout: out.stdout,
        stderr: out.stderr,
        fuel_used: 0,
    })
}

#[cfg(not(all(target_os = "linux", feature = "native")))]
pub fn run_native(
    _bytes: &[u8],
    _input: &[u8],
    _grants: &Requires,
    _cpu_secs: u64,
) -> Result<Output, RuntimeError> {
    Err(RuntimeError::Host(
        "native payloads require the `native` feature on Linux (landlock)".into(),
    ))
}

#[cfg(all(target_os = "linux", feature = "native"))]
fn set_rlimit(resource: libc::__rlimit_resource_t, limit: u64) {
    let rl = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // best-effort: a failed rlimit must not abort the exec
    unsafe {
        libc::setrlimit(resource, &rl);
    }
}

/// Compile the seccomp baseline: a DENY-LIST (default = allow) of syscalls no
/// compute payload needs and that enable privilege escalation, container
/// escape, or kernel tampering — the same class Docker/Wendy block by default.
/// Deny-list, not allow-list, so ordinary compute and I/O are never at risk of
/// a missing-syscall kill; matched syscalls return EPERM (graceful) rather than
/// SIGSYS. Compiled to BPF in the parent; only the install syscall runs in the
/// child.
#[cfg(all(target_os = "linux", feature = "native"))]
fn build_seccomp() -> Result<seccompiler::BpfProgram, String> {
    use seccompiler::{SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    // Syscalls to block. libc::SYS_* are arch-correct numbers.
    let blocked: &[libc::c_long] = &[
        libc::SYS_ptrace,            // debug/inject other processes
        libc::SYS_kexec_load,        // load a new kernel
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,       // load kernel modules
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_mount,             // filesystem topology
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_reboot,
        libc::SYS_bpf,               // load BPF programs
        libc::SYS_userfaultfd,       // classic exploitation primitive
        libc::SYS_process_vm_readv,  // cross-process memory
        libc::SYS_process_vm_writev,
        libc::SYS_perf_event_open,
        libc::SYS_setns,             // namespace entry
        libc::SYS_unshare,           // namespace creation / escape
        libc::SYS_add_key,           // kernel keyring
        libc::SYS_keyctl,
        libc::SYS_request_key,
        libc::SYS_acct,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_syslog,            // kernel ring buffer
    ];
    // Empty rule vector ⇒ unconditional match on that syscall.
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &nr in blocked {
        rules.insert(nr as i64, vec![]);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,               // default: allow everything else
        SeccompAction::Errno(libc::EPERM as u32), // blocked ⇒ EPERM
        std::env::consts::ARCH.try_into().map_err(|_| "unsupported arch".to_string())?,
    )
    .map_err(|e| e.to_string())?;
    filter.try_into().map_err(|e: seccompiler::BackendError| format!("{e:?}"))
}

/// A landlock ruleset created (rules added) in the parent; `restrict_self` is
/// deferred to the child. Holds the created ruleset's fd, which is `Send`.
#[cfg(all(target_os = "linux", feature = "native"))]
struct PreparedRuleset(landlock::RulesetCreated);

#[cfg(all(target_os = "linux", feature = "native"))]
impl PreparedRuleset {
    fn restrict_self_in_child(self) -> Result<(), String> {
        self.0.restrict_self().map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "native"))]
fn build_ruleset(
    exe_dir: &std::path::Path,
    scratch: &std::path::Path,
    grants: &Requires,
) -> Result<PreparedRuleset, String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    let abi = ABI::V2;
    let ro = AccessFs::from_read(abi); // includes Execute + ReadFile + ReadDir
    let rw = AccessFs::from_all(abi);
    let net_grant = grants.wasi.iter().any(|g| g == "net");

    let mut rs = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| e.to_string())?;
    // Network handling needs ABI V4; best-effort so V2 kernels simply don't
    // restrict net (documented — landlock net is a bonus tier).
    if let Ok(withnet) = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V4))
        .and_then(|r| r.handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp))
    {
        rs = withnet;
    }
    let mut created = rs.create().map_err(|e| e.to_string())?;

    // Add a path rule, SKIPPING any path that doesn't exist (opening its
    // O_PATH fd fails) — so an absent /lib64 or /etc/resolv.conf is a no-op,
    // not an error, and only real paths ever enter the ruleset.
    let mut add = |created: landlock::RulesetCreated,
                   path: &str,
                   access: landlock::BitFlags<AccessFs>|
     -> Result<landlock::RulesetCreated, String> {
        match PathFd::new(path) {
            Ok(fd) => created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| e.to_string()),
            Err(_) => Ok(created), // missing path → skip
        }
    };

    // read+execute: the payload's own dir and the system runtime dirs a
    // dynamic binary's loader + libraries live in.
    for p in [
        exe_dir.to_string_lossy().as_ref(),
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
    ] {
        created = add(created, p, ro)?;
    }
    // read: the specific loader/resolver files only — NOT all of /etc, so a
    // payload cannot enumerate host configuration it wasn't given.
    for p in [
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/etc/localtime",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
    ] {
        created = add(created, p, ro)?;
    }
    // read+write: the per-run scratch, plus any fs:<dir> the manifest grants.
    created = add(created, scratch.to_string_lossy().as_ref(), rw)?;
    for g in &grants.wasi {
        if let Some(p) = g.strip_prefix("fs:") {
            created = add(created, p, rw)?;
        }
    }
    // net: grant outbound TCP to the ports our payloads use when "net" is
    // granted; otherwise no net rules → bind/connect denied on ABI≥4 kernels.
    if net_grant {
        for port in [80u16, 443, 8080, 7266] {
            created = created
                .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(PreparedRuleset(created))
}
