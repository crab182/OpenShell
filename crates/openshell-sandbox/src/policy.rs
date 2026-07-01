// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox policy configuration.

use openshell_core::proto::{
    FilesystemPolicy as ProtoFilesystemPolicy, LandlockPolicy as ProtoLandlockPolicy,
    ProcessPolicy as ProtoProcessPolicy, SandboxPolicy as ProtoSandboxPolicy,
};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub version: u32,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub landlock: LandlockPolicy,
    pub process: ProcessPolicy,
}

#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    /// Read-only directory allow list.
    pub read_only: Vec<PathBuf>,

    /// Read-write directory allow list.
    pub read_write: Vec<PathBuf>,

    /// Automatically include the workdir as read-write.
    pub include_workdir: bool,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            include_workdir: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub proxy: Option<ProxyPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Block,
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum NetworkMode {
    #[default]
    Block,
    Proxy,
    Allow,
}

#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    /// TCP address for a local HTTP proxy (loopback-only).
    pub http_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct LandlockPolicy {
    pub compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessPolicy {
    /// User name to run the sandboxed process as.
    pub run_as_user: Option<String>,

    /// Group name to run the sandboxed process as.
    pub run_as_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum LandlockCompatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

// ============================================================================
// Proto to Rust type conversions
// ============================================================================

impl TryFrom<ProtoSandboxPolicy> for SandboxPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoSandboxPolicy) -> Result<Self, Self::Error> {
        // In cluster mode we always run with proxy networking so all egress
        // can be evaluated by OPA and `inference.local` is always addressable.
        let network = NetworkPolicy {
            mode: NetworkMode::Proxy,
            proxy: Some(ProxyPolicy { http_addr: None }),
        };

        Ok(Self {
            version: proto.version,
            filesystem: proto
                .filesystem
                .map(FilesystemPolicy::from)
                .unwrap_or_default(),
            network,
            landlock: proto.landlock.map(LandlockPolicy::from).unwrap_or_default(),
            process: proto.process.map(ProcessPolicy::from).unwrap_or_default(),
        })
    }
}

impl From<ProtoFilesystemPolicy> for FilesystemPolicy {
    fn from(proto: ProtoFilesystemPolicy) -> Self {
        Self {
            read_only: proto
                .read_only
                .into_iter()
                .map(|p| PathBuf::from(openshell_policy::normalize_path(&p)))
                .collect(),
            read_write: proto
                .read_write
                .into_iter()
                .map(|p| PathBuf::from(openshell_policy::normalize_path(&p)))
                .collect(),
            include_workdir: proto.include_workdir,
        }
    }
}

impl From<ProtoLandlockPolicy> for LandlockPolicy {
    fn from(proto: ProtoLandlockPolicy) -> Self {
        let compatibility = if proto.compatibility == "hard_requirement" {
            LandlockCompatibility::HardRequirement
        } else {
            LandlockCompatibility::BestEffort
        };
        Self { compatibility }
    }
}

impl From<ProtoProcessPolicy> for ProcessPolicy {
    fn from(proto: ProtoProcessPolicy) -> Self {
        Self {
            run_as_user: if proto.run_as_user.is_empty() {
                None
            } else {
                Some(proto.run_as_user)
            },
            run_as_group: if proto.run_as_group.is_empty() {
                None
            } else {
                Some(proto.run_as_group)
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A proto policy with only `version` set; every sub-policy is absent so we
    /// exercise the `unwrap_or_default()` branches.
    fn empty_proto(version: u32) -> ProtoSandboxPolicy {
        ProtoSandboxPolicy {
            version,
            ..Default::default()
        }
    }

    // ------------------------------------------------------------------ network

    /// Security invariant: in cluster mode the sandbox MUST always run with
    /// proxy networking so that every egress is evaluated by OPA. The proto's
    /// own network field is intentionally ignored — this test pins that
    /// behaviour so a future refactor can't silently let `Allow`/`Block` mode
    /// (i.e. unproxied egress) leak through.
    #[test]
    fn conversion_always_forces_proxy_networking() {
        let policy = SandboxPolicy::try_from(empty_proto(1)).unwrap();
        assert!(
            matches!(policy.network.mode, NetworkMode::Proxy),
            "expected egress to be forced through the proxy, got {:?}",
            policy.network.mode
        );
        // Proxy is present but the address is resolved later (None here), never
        // pre-bound to an attacker-controlled value from the proto.
        let proxy = policy.network.proxy.expect("proxy policy must be present");
        assert!(proxy.http_addr.is_none());
    }

    #[test]
    fn version_is_preserved() {
        let policy = SandboxPolicy::try_from(empty_proto(7)).unwrap();
        assert_eq!(policy.version, 7);
    }

    // --------------------------------------------------------------- filesystem

    #[test]
    fn absent_filesystem_uses_secure_defaults() {
        let policy = SandboxPolicy::try_from(empty_proto(1)).unwrap();
        assert!(policy.filesystem.read_only.is_empty());
        assert!(policy.filesystem.read_write.is_empty());
        // Default keeps the workdir writable; everything else is denied.
        assert!(policy.filesystem.include_workdir);
    }

    #[test]
    fn filesystem_paths_are_normalized_and_flags_preserved() {
        let proto = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(ProtoFilesystemPolicy {
                read_only: vec!["/data//foo/".to_string(), "/a/./b".to_string()],
                read_write: vec!["/work/".to_string()],
                include_workdir: false,
            }),
            ..Default::default()
        };

        let policy = SandboxPolicy::try_from(proto).unwrap();

        // Redundant separators, trailing slashes, and `.` components collapse so
        // that allow-list matching can't be defeated by path aliasing.
        assert_eq!(
            policy.filesystem.read_only,
            vec![PathBuf::from("/data/foo"), PathBuf::from("/a/b")],
        );
        assert_eq!(policy.filesystem.read_write, vec![PathBuf::from("/work")]);
        assert!(!policy.filesystem.include_workdir);
    }

    // ------------------------------------------------------------------ landlock

    #[test]
    fn landlock_hard_requirement_is_honoured() {
        let proto = ProtoSandboxPolicy {
            version: 1,
            landlock: Some(ProtoLandlockPolicy {
                compatibility: "hard_requirement".to_string(),
            }),
            ..Default::default()
        };
        let policy = SandboxPolicy::try_from(proto).unwrap();
        assert!(matches!(
            policy.landlock.compatibility,
            LandlockCompatibility::HardRequirement
        ));
    }

    #[test]
    fn landlock_unknown_or_empty_value_falls_back_to_best_effort() {
        for value in ["best_effort", "", "HARD_REQUIREMENT", "garbage"] {
            let proto = ProtoSandboxPolicy {
                version: 1,
                landlock: Some(ProtoLandlockPolicy {
                    compatibility: value.to_string(),
                }),
                ..Default::default()
            };
            let policy = SandboxPolicy::try_from(proto).unwrap();
            assert!(
                matches!(
                    policy.landlock.compatibility,
                    LandlockCompatibility::BestEffort
                ),
                "value {value:?} should map to BestEffort",
            );
        }
    }

    #[test]
    fn absent_landlock_defaults_to_best_effort() {
        let policy = SandboxPolicy::try_from(empty_proto(1)).unwrap();
        assert!(matches!(
            policy.landlock.compatibility,
            LandlockCompatibility::BestEffort
        ));
    }

    // ------------------------------------------------------------------- process

    #[test]
    fn process_empty_strings_become_none() {
        let proto = ProtoSandboxPolicy {
            version: 1,
            process: Some(ProtoProcessPolicy {
                run_as_user: String::new(),
                run_as_group: String::new(),
            }),
            ..Default::default()
        };
        let policy = SandboxPolicy::try_from(proto).unwrap();
        assert_eq!(policy.process.run_as_user, None);
        assert_eq!(policy.process.run_as_group, None);
    }

    #[test]
    fn process_non_empty_strings_are_wrapped_in_some() {
        let proto = ProtoSandboxPolicy {
            version: 1,
            process: Some(ProtoProcessPolicy {
                run_as_user: "agent".to_string(),
                run_as_group: "agents".to_string(),
            }),
            ..Default::default()
        };
        let policy = SandboxPolicy::try_from(proto).unwrap();
        assert_eq!(policy.process.run_as_user.as_deref(), Some("agent"));
        assert_eq!(policy.process.run_as_group.as_deref(), Some("agents"));
    }

    #[test]
    fn absent_process_defaults_to_no_user_or_group() {
        let policy = SandboxPolicy::try_from(empty_proto(1)).unwrap();
        assert_eq!(policy.process.run_as_user, None);
        assert_eq!(policy.process.run_as_group, None);
    }
}
