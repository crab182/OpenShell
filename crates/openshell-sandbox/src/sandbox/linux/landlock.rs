// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock filesystem sandboxing.

use crate::policy::{LandlockCompatibility, SandboxPolicy};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, PathFdError, Ruleset,
    RulesetAttr, RulesetCreatedAttr,
};
use miette::{IntoDiagnostic, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub fn apply(policy: &SandboxPolicy, workdir: Option<&str>) -> Result<()> {
    let (read_only, read_write) = resolve_paths(policy, workdir);

    if read_only.is_empty() && read_write.is_empty() {
        return Ok(());
    }

    let total_paths = read_only.len() + read_write.len();
    let abi = ABI::V2;
    info!(
        abi = ?abi,
        compatibility = ?policy.landlock.compatibility,
        read_only_paths = read_only.len(),
        read_write_paths = read_write.len(),
        "Applying Landlock filesystem sandbox"
    );

    let compatibility = &policy.landlock.compatibility;

    let result: Result<()> = (|| {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default();
        ruleset = ruleset
            .set_compatibility(compat_level(compatibility))
            .handle_access(access_all)
            .into_diagnostic()?;

        let mut ruleset = ruleset.create().into_diagnostic()?;
        let mut rules_applied: usize = 0;

        for path in &read_only {
            if let Some(path_fd) = try_open_path(path, compatibility)? {
                debug!(path = %path.display(), "Landlock allow read-only");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, access_read))
                    .into_diagnostic()?;
                rules_applied += 1;
            }
        }

        for path in &read_write {
            if let Some(path_fd) = try_open_path(path, compatibility)? {
                debug!(path = %path.display(), "Landlock allow read-write");
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, access_all))
                    .into_diagnostic()?;
                rules_applied += 1;
            }
        }

        if rules_applied == 0 {
            return Err(miette::miette!(
                "Landlock ruleset has zero valid paths — all {} path(s) failed to open. \
                 Refusing to apply an empty ruleset that would block all filesystem access.",
                total_paths,
            ));
        }

        let skipped = total_paths - rules_applied;
        info!(
            rules_applied,
            skipped, "Landlock ruleset built successfully"
        );

        ruleset.restrict_self().into_diagnostic()?;
        Ok(())
    })();

    finalize_result(result, compatibility)
}

/// Resolve the effective read-only / read-write path lists for `policy`, folding
/// `workdir` into the read-write set when requested (deduped). Pure, so the
/// path-selection logic can be unit tested without the Landlock LSM.
fn resolve_paths(policy: &SandboxPolicy, workdir: Option<&str>) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let read_only = policy.filesystem.read_only.clone();
    let mut read_write = policy.filesystem.read_write.clone();

    if policy.filesystem.include_workdir
        && let Some(dir) = workdir
    {
        let workdir_path = PathBuf::from(dir);
        if !read_write.contains(&workdir_path) {
            read_write.push(workdir_path);
        }
    }

    (read_only, read_write)
}

/// Apply the compatibility-mode outcome to the ruleset build `result`: a
/// hard-requirement propagates any error, while best-effort downgrades an error
/// to `Ok` and runs WITHOUT filesystem restrictions (logged loudly). This is the
/// central security tradeoff of the module, extracted so it can be tested
/// without installing a real ruleset.
fn finalize_result(result: Result<()>, compatibility: &LandlockCompatibility) -> Result<()> {
    if let Err(err) = result {
        if matches!(compatibility, LandlockCompatibility::BestEffort) {
            warn!(
                error = %err,
                "Landlock filesystem sandbox is UNAVAILABLE — running WITHOUT filesystem restrictions. \
                 Set landlock.compatibility to 'hard_requirement' to make this a fatal error."
            );
            return Ok(());
        }
        return Err(err);
    }

    Ok(())
}

/// Attempt to open a path for Landlock rule creation.
///
/// In `BestEffort` mode, inaccessible paths (missing, permission denied, symlink
/// loops, etc.) are skipped with a warning and `Ok(None)` is returned so the
/// caller can continue building the ruleset from the remaining valid paths.
///
/// In `HardRequirement` mode, any failure is fatal — the caller propagates the
/// error, which ultimately aborts sandbox startup.
fn try_open_path(path: &Path, compatibility: &LandlockCompatibility) -> Result<Option<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Ok(Some(fd)),
        Err(err) => {
            let reason = classify_path_fd_error(&err);
            let is_not_found = matches!(
                &err,
                PathFdError::OpenCall { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound
            );
            match compatibility {
                LandlockCompatibility::BestEffort => {
                    // NotFound is expected for stale baseline paths (e.g.
                    // /app baked into the server-stored policy but absent
                    // in this container image).  Log at debug! to avoid
                    // polluting SSH exec stdout — the pre_exec hook
                    // inherits the tracing subscriber whose writer targets
                    // fd 1 (the pipe/PTY).
                    //
                    // Other errors (permission denied, symlink loops, etc.)
                    // are genuinely unexpected and logged at warn!.
                    if is_not_found {
                        debug!(
                            path = %path.display(),
                            reason,
                            "Skipping non-existent Landlock path (best-effort mode)"
                        );
                    } else {
                        warn!(
                            path = %path.display(),
                            error = %err,
                            reason,
                            "Skipping inaccessible Landlock path (best-effort mode)"
                        );
                    }
                    Ok(None)
                }
                LandlockCompatibility::HardRequirement => Err(miette::miette!(
                    "Landlock path unavailable in hard_requirement mode: {} ({}): {}",
                    path.display(),
                    reason,
                    err,
                )),
            }
        }
    }
}

/// Classify a [`PathFdError`] into a human-readable reason.
///
/// `PathFd::new()` wraps `open(path, O_PATH | O_CLOEXEC)` which can fail for
/// several reasons beyond simple non-existence. The `PathFdError::OpenCall`
/// variant wraps the underlying `std::io::Error`.
fn classify_path_fd_error(err: &PathFdError) -> &'static str {
    match err {
        PathFdError::OpenCall { source, .. } => classify_io_error(source),
        // PathFdError is #[non_exhaustive], handle future variants gracefully.
        _ => "unexpected error",
    }
}

/// Classify a `std::io::Error` into a human-readable reason string.
fn classify_io_error(err: &std::io::Error) -> &'static str {
    match err.kind() {
        std::io::ErrorKind::NotFound => "path does not exist",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        _ => match err.raw_os_error() {
            Some(40) => "too many symlink levels",           // ELOOP
            Some(36) => "path name too long",                // ENAMETOOLONG
            Some(20) => "path component is not a directory", // ENOTDIR
            _ => "unexpected error",
        },
    }
}

fn compat_level(level: &LandlockCompatibility) -> CompatLevel {
    match level {
        LandlockCompatibility::BestEffort => CompatLevel::BestEffort,
        LandlockCompatibility::HardRequirement => CompatLevel::HardRequirement,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_open_path_best_effort_returns_none_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::BestEffort,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn try_open_path_hard_requirement_errors_for_missing_path() {
        let result = try_open_path(
            &PathBuf::from("/nonexistent/openshell/test/path"),
            &LandlockCompatibility::HardRequirement,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hard_requirement"),
            "error should mention hard_requirement mode: {err_msg}"
        );
        assert!(
            err_msg.contains("does not exist"),
            "error should include the classified reason: {err_msg}"
        );
    }

    #[test]
    fn try_open_path_succeeds_for_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let result = try_open_path(dir.path(), &LandlockCompatibility::BestEffort);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn classify_not_found() {
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(classify_io_error(&err), "path does not exist");
    }

    #[test]
    fn classify_permission_denied() {
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(classify_io_error(&err), "permission denied");
    }

    #[test]
    fn classify_symlink_loop() {
        let err = std::io::Error::from_raw_os_error(libc::ELOOP);
        assert_eq!(classify_io_error(&err), "too many symlink levels");
    }

    #[test]
    fn classify_name_too_long() {
        let err = std::io::Error::from_raw_os_error(libc::ENAMETOOLONG);
        assert_eq!(classify_io_error(&err), "path name too long");
    }

    #[test]
    fn classify_not_a_directory() {
        let err = std::io::Error::from_raw_os_error(libc::ENOTDIR);
        assert_eq!(classify_io_error(&err), "path component is not a directory");
    }

    fn fs_policy(
        read_only: Vec<PathBuf>,
        read_write: Vec<PathBuf>,
        include_workdir: bool,
    ) -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: crate::policy::FilesystemPolicy {
                read_only,
                read_write,
                include_workdir,
            },
            network: crate::policy::NetworkPolicy::default(),
            landlock: crate::policy::LandlockPolicy::default(),
            process: crate::policy::ProcessPolicy::default(),
        }
    }

    #[test]
    fn resolve_paths_appends_workdir_as_read_write() {
        let (ro, rw) = resolve_paths(&fs_policy(vec![], vec![], true), Some("/work"));
        assert!(ro.is_empty());
        assert_eq!(rw, vec![PathBuf::from("/work")]);
    }

    #[test]
    fn resolve_paths_does_not_duplicate_existing_workdir() {
        let policy = fs_policy(vec![], vec![PathBuf::from("/work")], true);
        let (_, rw) = resolve_paths(&policy, Some("/work"));
        assert_eq!(
            rw,
            vec![PathBuf::from("/work")],
            "an already-present workdir must not be duplicated"
        );
    }

    #[test]
    fn resolve_paths_skips_workdir_when_not_included() {
        let (ro, rw) = resolve_paths(&fs_policy(vec![], vec![], false), Some("/work"));
        assert!(
            ro.is_empty() && rw.is_empty(),
            "workdir must be ignored when include_workdir is false"
        );
    }

    #[test]
    fn resolve_paths_empty_policy_stays_empty() {
        // This is the precondition for apply()'s early Ok return.
        let (ro, rw) = resolve_paths(&fs_policy(vec![], vec![], true), None);
        assert!(ro.is_empty() && rw.is_empty());
    }

    #[test]
    fn finalize_best_effort_downgrades_error_to_ok() {
        // The central tradeoff: a failed ruleset build in best-effort mode runs
        // the process WITHOUT a filesystem sandbox instead of aborting.
        let out = finalize_result(
            Err(miette::miette!("ruleset failed")),
            &LandlockCompatibility::BestEffort,
        );
        assert!(
            out.is_ok(),
            "best-effort must swallow the error and continue"
        );
    }

    #[test]
    fn finalize_hard_requirement_propagates_error() {
        let out = finalize_result(
            Err(miette::miette!("ruleset failed")),
            &LandlockCompatibility::HardRequirement,
        );
        assert!(out.is_err(), "hard-requirement must propagate the error");
    }

    #[test]
    fn finalize_success_passes_through_in_both_modes() {
        assert!(finalize_result(Ok(()), &LandlockCompatibility::BestEffort).is_ok());
        assert!(finalize_result(Ok(()), &LandlockCompatibility::HardRequirement).is_ok());
    }

    #[test]
    fn classify_unknown_error() {
        let err = std::io::Error::from_raw_os_error(libc::EIO);
        assert_eq!(classify_io_error(&err), "unexpected error");
    }

    #[test]
    fn classify_path_fd_error_extracts_io_error() {
        // Use PathFd::new on a non-existent path to get a real PathFdError
        // (the OpenCall variant is #[non_exhaustive] and can't be constructed directly).
        let err = PathFd::new("/nonexistent/openshell/classify/test").unwrap_err();
        assert_eq!(classify_path_fd_error(&err), "path does not exist");
    }

    #[test]
    fn classify_path_fd_error_extracts_not_a_directory() {
        // Opening a path *beneath* a regular file yields ENOTDIR from open(2).
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("regular_file");
        std::fs::write(&file_path, b"x").unwrap();
        let beneath = file_path.join("child");
        let err = PathFd::new(&beneath).unwrap_err();
        assert_eq!(
            classify_path_fd_error(&err),
            "path component is not a directory"
        );
    }

    #[test]
    fn classify_io_error_falls_back_for_kind_without_raw_errno() {
        // An error constructed without a raw OS errno (only an ErrorKind) that
        // is not NotFound / PermissionDenied must take the `raw_os_error() ==
        // None` branch and resolve to the generic reason.
        let err = std::io::Error::new(std::io::ErrorKind::Other, "synthetic");
        assert_eq!(classify_io_error(&err), "unexpected error");
    }

    #[test]
    fn classify_io_error_unhandled_errno_is_unexpected() {
        // EISDIR is a real errno but not one of the specifically classified
        // values, so it must fall through to the generic reason rather than
        // being mislabelled.
        let err = std::io::Error::from_raw_os_error(libc::EISDIR);
        assert_eq!(classify_io_error(&err), "unexpected error");
    }

    #[test]
    fn compat_level_best_effort_maps_to_best_effort() {
        assert_eq!(
            compat_level(&LandlockCompatibility::BestEffort),
            CompatLevel::BestEffort
        );
    }

    #[test]
    fn compat_level_hard_requirement_maps_to_hard_requirement() {
        assert_eq!(
            compat_level(&LandlockCompatibility::HardRequirement),
            CompatLevel::HardRequirement
        );
    }

    #[test]
    fn try_open_path_succeeds_for_existing_file() {
        // A regular file (not just a directory) is a valid Landlock path target.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("allowed_file");
        std::fs::write(&file_path, b"data").unwrap();
        let result = try_open_path(&file_path, &LandlockCompatibility::BestEffort);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn try_open_path_hard_requirement_succeeds_for_existing_path() {
        // Hard-requirement mode must still open paths that exist; failure is
        // only fatal when the path is genuinely inaccessible.
        let dir = tempfile::tempdir().unwrap();
        let result = try_open_path(dir.path(), &LandlockCompatibility::HardRequirement);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn try_open_path_hard_requirement_error_includes_path() {
        let missing = PathBuf::from("/nonexistent/openshell/hard/req/path");
        let err = try_open_path(&missing, &LandlockCompatibility::HardRequirement)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("/nonexistent/openshell/hard/req/path"),
            "error should name the offending path: {err}"
        );
    }
}
