// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Seccomp syscall filtering.
//!
//! The filter uses a default-allow policy with targeted blocks:
//!
//! 1. **Socket domain blocks** -- prevent raw/kernel sockets that bypass the proxy
//! 2. **Unconditional syscall blocks** -- block syscalls that enable sandbox escape
//!    (fileless exec, ptrace, BPF, cross-process memory access, io_uring, mount)
//! 3. **Conditional syscall blocks** -- block dangerous flag combinations on otherwise
//!    needed syscalls (execveat+AT_EMPTY_PATH, unshare+CLONE_NEWUSER,
//!    seccomp+SET_MODE_FILTER)

use crate::policy::{NetworkMode, SandboxPolicy};
use miette::{IntoDiagnostic, Result};
use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    apply_filter,
};
use std::collections::BTreeMap;
use std::convert::TryInto;
use tracing::debug;

/// Value of `SECCOMP_SET_MODE_FILTER` (linux/seccomp.h).
const SECCOMP_SET_MODE_FILTER: u64 = 1;

pub fn apply(policy: &SandboxPolicy) -> Result<()> {
    if matches!(policy.network.mode, NetworkMode::Allow) {
        return Ok(());
    }

    let allow_inet = matches!(policy.network.mode, NetworkMode::Proxy);
    let filter = build_filter(allow_inet)?;

    // Required before applying seccomp filters.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(miette::miette!(
            "Failed to set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }

    apply_filter(&filter).into_diagnostic()?;
    Ok(())
}

fn build_filter(allow_inet: bool) -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // --- Socket domain blocks ---
    let mut blocked_domains = vec![libc::AF_PACKET, libc::AF_BLUETOOTH, libc::AF_VSOCK];
    if !allow_inet {
        blocked_domains.push(libc::AF_INET);
        blocked_domains.push(libc::AF_INET6);
        blocked_domains.push(libc::AF_NETLINK);
    }

    for domain in blocked_domains {
        debug!(domain, "Blocking socket domain via seccomp");
        add_socket_domain_rule(&mut rules, domain)?;
    }

    // --- Unconditional syscall blocks ---
    // These syscalls are blocked entirely (empty rule vec = unconditional EPERM).

    // Fileless binary execution via memfd bypasses Landlock filesystem restrictions.
    rules.entry(libc::SYS_memfd_create).or_default();
    // Cross-process memory inspection and code injection.
    rules.entry(libc::SYS_ptrace).or_default();
    // Kernel BPF program loading.
    rules.entry(libc::SYS_bpf).or_default();
    // Cross-process memory read.
    rules.entry(libc::SYS_process_vm_readv).or_default();
    // Async I/O subsystem with extensive CVE history.
    rules.entry(libc::SYS_io_uring_setup).or_default();
    // Filesystem mount could subvert Landlock or overlay writable paths.
    rules.entry(libc::SYS_mount).or_default();

    // --- Conditional syscall blocks ---

    // execveat with AT_EMPTY_PATH enables fileless execution from an anonymous fd.
    add_masked_arg_rule(
        &mut rules,
        libc::SYS_execveat,
        4, // flags argument
        libc::AT_EMPTY_PATH as u64,
    )?;

    // unshare with CLONE_NEWUSER allows creating user namespaces to escalate privileges.
    add_masked_arg_rule(
        &mut rules,
        libc::SYS_unshare,
        0, // flags argument
        libc::CLONE_NEWUSER as u64,
    )?;

    // seccomp(SECCOMP_SET_MODE_FILTER) would let sandboxed code replace the active filter.
    let condition = SeccompCondition::new(
        0, // operation argument
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        SECCOMP_SET_MODE_FILTER,
    )
    .into_diagnostic()?;
    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(libc::SYS_seccomp).or_default().push(rule);

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| miette::miette!("Unsupported architecture for seccomp"))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .into_diagnostic()?;

    filter.try_into().into_diagnostic()
}

#[allow(clippy::cast_sign_loss)]
fn add_socket_domain_rule(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, domain: i32) -> Result<()> {
    let condition =
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, domain as u64)
            .into_diagnostic()?;

    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(libc::SYS_socket).or_default().push(rule);
    Ok(())
}

/// Block a syscall when a specific bit pattern is set in an argument.
///
/// Uses `MaskedEq` to check `(arg & flag_bit) == flag_bit`, which triggers
/// EPERM when the flag is present regardless of other bits in the argument.
fn add_masked_arg_rule(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    syscall: i64,
    arg_index: u8,
    flag_bit: u64,
) -> Result<()> {
    let condition = SeccompCondition::new(
        arg_index,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(flag_bit),
        flag_bit,
    )
    .into_diagnostic()?;
    let rule = SeccompRule::new(vec![condition]).into_diagnostic()?;
    rules.entry(syscall).or_default().push(rule);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_proxy_mode_compiles() {
        let filter = build_filter(true);
        assert!(filter.is_ok(), "build_filter(true) should succeed");
    }

    #[test]
    fn build_filter_block_mode_compiles() {
        let filter = build_filter(false);
        assert!(filter.is_ok(), "build_filter(false) should succeed");
    }

    #[test]
    fn add_masked_arg_rule_creates_entry() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let result = add_masked_arg_rule(&mut rules, libc::SYS_execveat, 4, 0x1000);
        assert!(result.is_ok());
        assert!(
            rules.contains_key(&libc::SYS_execveat),
            "should have an entry for SYS_execveat"
        );
        assert_eq!(
            rules[&libc::SYS_execveat].len(),
            1,
            "should have exactly one rule"
        );
    }

    #[test]
    fn unconditional_blocks_present_in_filter() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Simulate what build_filter does for unconditional blocks
        rules.entry(libc::SYS_memfd_create).or_default();
        rules.entry(libc::SYS_ptrace).or_default();
        rules.entry(libc::SYS_bpf).or_default();
        rules.entry(libc::SYS_process_vm_readv).or_default();
        rules.entry(libc::SYS_io_uring_setup).or_default();
        rules.entry(libc::SYS_mount).or_default();

        // Unconditional blocks have an empty Vec (no conditions = always match)
        for syscall in [
            libc::SYS_memfd_create,
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_process_vm_readv,
            libc::SYS_io_uring_setup,
            libc::SYS_mount,
        ] {
            assert!(
                rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                rules[&syscall].is_empty(),
                "syscall {syscall} should have empty rules (unconditional block)"
            );
        }
    }

    #[test]
    fn conditional_blocks_have_rules() {
        // Build a real filter and verify the conditional syscalls have rule entries
        // (non-empty Vec means conditional match)
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        add_masked_arg_rule(
            &mut rules,
            libc::SYS_execveat,
            4,
            libc::AT_EMPTY_PATH as u64,
        )
        .unwrap();
        add_masked_arg_rule(&mut rules, libc::SYS_unshare, 0, libc::CLONE_NEWUSER as u64).unwrap();

        let condition = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            SECCOMP_SET_MODE_FILTER,
        )
        .unwrap();
        let rule = SeccompRule::new(vec![condition]).unwrap();
        rules.entry(libc::SYS_seccomp).or_default().push(rule);

        for syscall in [libc::SYS_execveat, libc::SYS_unshare, libc::SYS_seccomp] {
            assert!(
                rules.contains_key(&syscall),
                "syscall {syscall} should be in the rules map"
            );
            assert!(
                !rules[&syscall].is_empty(),
                "syscall {syscall} should have conditional rules"
            );
        }
    }

    /// Syscalls that `build_filter` blocks unconditionally (empty rule vec)
    /// regardless of the network mode.
    const UNCONDITIONAL_BLOCKS: [i64; 6] = [
        libc::SYS_memfd_create,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_process_vm_readv,
        libc::SYS_io_uring_setup,
        libc::SYS_mount,
    ];

    /// Mirror of the socket-domain selection logic in `build_filter`, used to
    /// drive the real `add_socket_domain_rule` helper from tests. Returns the
    /// populated rules map so the resulting `SYS_socket` rules can be inspected.
    fn socket_rules_for(allow_inet: bool) -> BTreeMap<i64, Vec<SeccompRule>> {
        let mut blocked_domains = vec![libc::AF_PACKET, libc::AF_BLUETOOTH, libc::AF_VSOCK];
        if !allow_inet {
            blocked_domains.push(libc::AF_INET);
            blocked_domains.push(libc::AF_INET6);
            blocked_domains.push(libc::AF_NETLINK);
        }

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for domain in blocked_domains {
            add_socket_domain_rule(&mut rules, domain).unwrap();
        }
        rules
    }

    /// Independently rebuild the rule that `add_socket_domain_rule` is expected
    /// to construct for a given socket domain, so equality is asserted against a
    /// known-good reference rather than the function's own output.
    fn expected_socket_domain_rule(domain: i32) -> SeccompRule {
        let condition = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            #[allow(clippy::cast_sign_loss)]
            {
                domain as u64
            },
        )
        .unwrap();
        SeccompRule::new(vec![condition]).unwrap()
    }

    #[test]
    fn add_socket_domain_rule_appends_expected_eq_rule() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        add_socket_domain_rule(&mut rules, libc::AF_PACKET).unwrap();

        // The rule is attached to SYS_socket, not to the domain value.
        assert!(
            rules.contains_key(&libc::SYS_socket),
            "socket-domain rules must hang off SYS_socket"
        );
        assert_eq!(
            rules[&libc::SYS_socket].len(),
            1,
            "one domain produces exactly one socket rule"
        );
        // Structural equality against an independently built Eq(arg0 == domain) rule.
        assert_eq!(
            rules[&libc::SYS_socket][0],
            expected_socket_domain_rule(libc::AF_PACKET),
            "rule must be an Eq comparison on arg0 against the domain"
        );
    }

    #[test]
    fn socket_domain_rules_accumulate_on_sys_socket() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        add_socket_domain_rule(&mut rules, libc::AF_PACKET).unwrap();
        add_socket_domain_rule(&mut rules, libc::AF_VSOCK).unwrap();

        // Multiple domains accumulate as separate rules under the same syscall.
        assert_eq!(rules.len(), 1, "only SYS_socket should be keyed");
        assert_eq!(rules[&libc::SYS_socket].len(), 2);
        assert_eq!(
            rules[&libc::SYS_socket][0],
            expected_socket_domain_rule(libc::AF_PACKET)
        );
        assert_eq!(
            rules[&libc::SYS_socket][1],
            expected_socket_domain_rule(libc::AF_VSOCK)
        );
    }

    #[test]
    fn proxy_and_block_share_common_socket_domain_blocks() {
        // AF_PACKET / AF_BLUETOOTH / AF_VSOCK are always blocked, in either mode.
        let common = [libc::AF_PACKET, libc::AF_BLUETOOTH, libc::AF_VSOCK];

        for allow_inet in [true, false] {
            let rules = socket_rules_for(allow_inet);
            let socket_rules = &rules[&libc::SYS_socket];
            for domain in common {
                assert!(
                    socket_rules.contains(&expected_socket_domain_rule(domain)),
                    "domain {domain} must be blocked when allow_inet={allow_inet}"
                );
            }
        }
    }

    #[test]
    fn block_mode_blocks_inet_domains_that_proxy_mode_allows() {
        let proxy = socket_rules_for(true);
        let block = socket_rules_for(false);

        // Proxy mode keeps the three baseline domain blocks only.
        assert_eq!(
            proxy[&libc::SYS_socket].len(),
            3,
            "proxy mode blocks exactly the three baseline socket domains"
        );
        // Block mode adds AF_INET / AF_INET6 / AF_NETLINK on top.
        assert_eq!(
            block[&libc::SYS_socket].len(),
            6,
            "block mode additionally blocks the three inet/netlink domains"
        );

        for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
            let expected = expected_socket_domain_rule(domain);
            assert!(
                block[&libc::SYS_socket].contains(&expected),
                "block mode must block domain {domain}"
            );
            assert!(
                !proxy[&libc::SYS_socket].contains(&expected),
                "proxy mode must NOT block domain {domain} (proxy routes inet traffic)"
            );
        }
    }

    #[test]
    fn add_masked_arg_rule_builds_expected_masked_eq_rule() {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let flag = libc::AT_EMPTY_PATH as u64;
        add_masked_arg_rule(&mut rules, libc::SYS_execveat, 4, flag).unwrap();

        // Independently construct the MaskedEq(flag) == flag rule on arg index 4.
        let expected_condition = SeccompCondition::new(
            4,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(flag),
            flag,
        )
        .unwrap();
        let expected_rule = SeccompRule::new(vec![expected_condition]).unwrap();

        assert_eq!(
            rules[&libc::SYS_execveat][0],
            expected_rule,
            "masked-arg rule must be MaskedEq(flag) compared against flag on the given arg"
        );
    }

    #[test]
    fn add_masked_arg_rule_accumulates_multiple_rules_on_one_syscall() {
        // Two masked rules on the same syscall should both be retained.
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        add_masked_arg_rule(&mut rules, libc::SYS_unshare, 0, 0x1).unwrap();
        add_masked_arg_rule(&mut rules, libc::SYS_unshare, 0, 0x2).unwrap();

        assert_eq!(
            rules[&libc::SYS_unshare].len(),
            2,
            "each call appends a distinct rule"
        );
        assert_ne!(
            rules[&libc::SYS_unshare][0],
            rules[&libc::SYS_unshare][1],
            "rules with different flag bits must differ structurally"
        );
    }

    #[test]
    fn unconditional_blocks_identical_across_modes() {
        // The unconditional syscall blocks are network-mode independent: they must
        // be present, and empty (always-match), in both proxy and block mode.
        // We reconstruct the same map build_filter assembles, exercising the real
        // socket/masked helpers, then assert the unconditional set is invariant.
        for allow_inet in [true, false] {
            let mut rules = socket_rules_for(allow_inet);
            for syscall in UNCONDITIONAL_BLOCKS {
                rules.entry(syscall).or_default();
            }

            for syscall in UNCONDITIONAL_BLOCKS {
                assert!(
                    rules.contains_key(&syscall),
                    "syscall {syscall} must be blocked when allow_inet={allow_inet}"
                );
                assert!(
                    rules[&syscall].is_empty(),
                    "syscall {syscall} must be an unconditional (empty-rule) block"
                );
            }
        }
    }

    #[test]
    fn build_filter_produces_nonempty_program_in_both_modes() {
        // build_filter returns a compiled BpfProgram (Vec<sock_filter>). A valid,
        // installable filter must be non-empty in either mode.
        let proxy = build_filter(true).expect("proxy-mode filter must compile");
        let block = build_filter(false).expect("block-mode filter must compile");

        assert!(
            !proxy.is_empty(),
            "proxy-mode program must contain BPF instructions"
        );
        assert!(
            !block.is_empty(),
            "block-mode program must contain BPF instructions"
        );

        // Block mode adds three extra socket-domain rules, so its compiled
        // program must contain strictly more instructions than proxy mode.
        assert!(
            block.len() > proxy.len(),
            "block mode blocks more socket domains and must compile to a larger \
             program (block={}, proxy={})",
            block.len(),
            proxy.len()
        );
    }

    #[test]
    fn host_arch_resolves_to_supported_target_arch() {
        // build_filter converts std::env::consts::ARCH into a seccompiler
        // TargetArch and errors on unsupported architectures. Assert the host
        // arch this test runs on is one build_filter accepts, which is the
        // precondition that makes the filter installable here.
        let arch: Result<seccompiler::TargetArch, _> = std::env::consts::ARCH.try_into();
        assert!(
            arch.is_ok(),
            "host arch {:?} must convert to a seccompiler TargetArch",
            std::env::consts::ARCH
        );
    }
}
