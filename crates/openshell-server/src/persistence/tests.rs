// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{DraftChunkRecord, ObjectId, ObjectName, ObjectType, Store, generate_name};
use openshell_core::proto::ObjectForTest;

#[tokio::test]
async fn sqlite_put_get_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload")
        .await
        .unwrap();

    let record = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.id, "abc");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn sqlite_updates_timestamp() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload")
        .await
        .unwrap();

    let first = store.get("sandbox", "abc").await.unwrap().unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload2")
        .await
        .unwrap();

    let second = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert!(second.updated_at_ms >= first.updated_at_ms);
    assert_eq!(second.payload, b"payload2");
}

#[tokio::test]
async fn sqlite_list_paging() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let name = format!("name-{idx}");
        let payload = format!("payload-{idx}");
        store
            .put("sandbox", &id, &name, payload.as_bytes())
            .await
            .unwrap();
    }

    let records = store.list("sandbox", 2, 1).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "name-1");
    assert_eq!(records[1].name, "name-2");
}

#[tokio::test]
async fn sqlite_delete_behavior() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "abc", "my-sandbox", b"payload")
        .await
        .unwrap();

    let deleted = store.delete("sandbox", "abc").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete("sandbox", "missing").await.unwrap();
    assert!(!deleted_again);
}

#[tokio::test]
async fn sqlite_protobuf_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let object = ObjectForTest {
        id: "abc".to_string(),
        name: "test-object".to_string(),
        count: 42,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message::<ObjectForTest>(&object.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(loaded.id, object.id);
    assert_eq!(loaded.name, object.name);
    assert_eq!(loaded.count, object.count);
}

#[tokio::test]
async fn sqlite_get_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "my-sandbox", b"payload")
        .await
        .unwrap();

    let record = store
        .get_by_name("sandbox", "my-sandbox")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id, "id-1");
    assert_eq!(record.name, "my-sandbox");
    assert_eq!(record.payload, b"payload");

    let missing = store.get_by_name("sandbox", "no-such-name").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_get_message_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let object = ObjectForTest {
        id: "uid-1".to_string(),
        name: "my-test".to_string(),
        count: 7,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message_by_name::<ObjectForTest>("my-test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, "uid-1");
    assert_eq!(loaded.name, "my-test");
    assert_eq!(loaded.count, 7);

    let missing = store
        .get_message_by_name::<ObjectForTest>("no-such-name")
        .await
        .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn sqlite_delete_by_name() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "my-sandbox", b"payload")
        .await
        .unwrap();

    let deleted = store.delete_by_name("sandbox", "my-sandbox").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete_by_name("sandbox", "my-sandbox").await.unwrap();
    assert!(!deleted_again);

    let gone = store.get("sandbox", "id-1").await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn sqlite_name_unique_per_object_type() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "id-1", "shared-name", b"payload1")
        .await
        .unwrap();

    // Same name, same object_type, different id -> should fail (unique constraint).
    let result = store
        .put("sandbox", "id-2", "shared-name", b"payload2")
        .await;
    assert!(result.is_err());

    // Same name, different object_type -> should succeed.
    store
        .put("secret", "id-3", "shared-name", b"payload3")
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_id_globally_unique() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put("sandbox", "same-id", "name-a", b"payload1")
        .await
        .unwrap();

    // Same id, different object_type -> the upsert is a no-op (WHERE
    // clause prevents updating a row with a different object_type).
    // The original row is preserved unchanged.
    store
        .put("secret", "same-id", "name-b", b"payload2")
        .await
        .unwrap();

    // Original row is untouched.
    let record = store.get("sandbox", "same-id").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.payload, b"payload1");

    // The secret was not inserted.
    let missing = store.get("secret", "same-id").await.unwrap();
    assert!(missing.is_none());
}

#[test]
fn generate_name_format() {
    for _ in 0..100 {
        let name = generate_name();
        assert_eq!(name.len(), 6);
        assert!(name.chars().all(|c| c.is_ascii_lowercase()));
    }
}

impl ObjectType for ObjectForTest {
    fn object_type() -> &'static str {
        "object_for_test"
    }
}

impl ObjectId for ObjectForTest {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for ObjectForTest {
    fn object_name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// Policy revision tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_put_and_get_latest() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"policy-v1", "hash1")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 1);
    assert_eq!(latest.policy_hash, "hash1");
    assert_eq!(latest.status, "pending");
    assert_eq!(latest.policy_payload, b"policy-v1");

    // Add version 2
    store
        .put_policy_revision("p2", "sandbox-1", 2, b"policy-v2", "hash2")
        .await
        .unwrap();

    let latest = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    assert_eq!(latest.version, 2);
    assert_eq!(latest.policy_hash, "hash2");
}

#[tokio::test]
async fn policy_get_by_version() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, b"v2", "h2")
        .await
        .unwrap();

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.version, 1);
    assert_eq!(v1.policy_hash, "h1");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(v2.policy_hash, "h2");

    let none = store.get_policy_by_version("sandbox-1", 99).await.unwrap();
    assert!(none.is_none());
}

#[tokio::test]
async fn policy_update_status_and_get_loaded() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();

    // No loaded policy yet.
    let loaded = store.get_latest_loaded_policy("sandbox-1").await.unwrap();
    assert!(loaded.is_none());

    // Mark as loaded.
    let updated = store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();
    assert!(updated);

    let loaded = store
        .get_latest_loaded_policy("sandbox-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.status, "loaded");
    assert_eq!(loaded.loaded_at_ms, Some(1000));
}

#[tokio::test]
async fn policy_status_failed_with_error() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();

    store
        .update_policy_status("sandbox-1", 1, "failed", Some("L7 validation error"), None)
        .await
        .unwrap();

    let record = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.status, "failed");
    assert_eq!(record.load_error.as_deref(), Some("L7 validation error"));
}

#[tokio::test]
async fn policy_supersede_older() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, b"v2", "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", 3, b"v3", "h3")
        .await
        .unwrap();

    // Mark v1 as loaded.
    store
        .update_policy_status("sandbox-1", 1, "loaded", None, Some(1000))
        .await
        .unwrap();

    // Supersede all older revisions (pending + loaded) before v3.
    let count = store
        .supersede_older_policies("sandbox-1", 3)
        .await
        .unwrap();
    assert_eq!(count, 2); // v1 (loaded) + v2 (pending) both < v3

    let v1 = store
        .get_policy_by_version("sandbox-1", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1.status, "superseded");

    let v2 = store
        .get_policy_by_version("sandbox-1", 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2.status, "superseded");

    let v3 = store
        .get_policy_by_version("sandbox-1", 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v3.status, "pending"); // still pending (not < 3)
}

#[tokio::test]
async fn policy_list_ordered_by_version_desc() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-1", 2, b"v2", "h2")
        .await
        .unwrap();
    store
        .put_policy_revision("p3", "sandbox-1", 3, b"v3", "h3")
        .await
        .unwrap();

    let records = store.list_policies("sandbox-1", 10, 0).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
    assert_eq!(records[2].version, 1);

    // Test with limit.
    let records = store.list_policies("sandbox-1", 2, 0).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].version, 3);
    assert_eq!(records[1].version, 2);
}

#[tokio::test]
async fn policy_isolation_between_sandboxes() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_policy_revision("p1", "sandbox-1", 1, b"v1", "h1")
        .await
        .unwrap();
    store
        .put_policy_revision("p2", "sandbox-2", 1, b"v1-s2", "h2")
        .await
        .unwrap();

    let s1 = store.get_latest_policy("sandbox-1").await.unwrap().unwrap();
    let s2 = store.get_latest_policy("sandbox-2").await.unwrap().unwrap();

    assert_eq!(s1.policy_payload, b"v1");
    assert_eq!(s2.policy_payload, b"v1-s2");
}

// ---------------------------------------------------------------------------
// Connect / scheme handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_rejects_unsupported_scheme() {
    let result = Store::connect("mysql://localhost/db").await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Draft policy chunk tests
// ---------------------------------------------------------------------------

/// Build a `DraftChunkRecord` with sensible defaults for tests, overriding
/// the fields that matter for dedup and lifecycle assertions.
fn draft_chunk(
    id: &str,
    sandbox_id: &str,
    host: &str,
    port: i32,
    binary: &str,
) -> DraftChunkRecord {
    DraftChunkRecord {
        id: id.to_string(),
        sandbox_id: sandbox_id.to_string(),
        draft_version: 1,
        status: "pending".to_string(),
        rule_name: format!("allow-{host}-{port}"),
        proposed_rule: b"rule-payload".to_vec(),
        rationale: "agent requested this endpoint".to_string(),
        security_notes: "low risk".to_string(),
        confidence: 0.9,
        created_at_ms: 1000,
        decided_at_ms: None,
        host: host.to_string(),
        port,
        binary: binary.to_string(),
        hit_count: 1,
        first_seen_ms: 1000,
        last_seen_ms: 1000,
    }
}

#[tokio::test]
async fn draft_chunk_put_and_get_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let chunk = draft_chunk("dc1", "sandbox-1", "api.example.com", 443, "/usr/bin/curl");
    store.put_draft_chunk(&chunk).await.unwrap();

    let loaded = store.get_draft_chunk("dc1").await.unwrap().unwrap();
    assert_eq!(loaded.id, "dc1");
    assert_eq!(loaded.sandbox_id, "sandbox-1");
    assert_eq!(loaded.draft_version, 1);
    assert_eq!(loaded.status, "pending");
    assert_eq!(loaded.rule_name, "allow-api.example.com-443");
    assert_eq!(loaded.proposed_rule, b"rule-payload");
    assert_eq!(loaded.rationale, "agent requested this endpoint");
    assert_eq!(loaded.security_notes, "low risk");
    assert!((loaded.confidence - 0.9).abs() < f64::EPSILON);
    assert_eq!(loaded.host, "api.example.com");
    assert_eq!(loaded.port, 443);
    assert_eq!(loaded.binary, "/usr/bin/curl");
    assert_eq!(loaded.hit_count, 1);
    assert_eq!(loaded.first_seen_ms, 1000);
    assert_eq!(loaded.last_seen_ms, 1000);
    assert_eq!(loaded.created_at_ms, 1000);
    assert_eq!(loaded.decided_at_ms, None);
}

#[tokio::test]
async fn draft_chunk_get_missing_returns_none() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let missing = store.get_draft_chunk("no-such-id").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn draft_chunk_upsert_bumps_hit_count_and_last_seen() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let first = draft_chunk("dc1", "sandbox-1", "api.example.com", 443, "/usr/bin/curl");
    store.put_draft_chunk(&first).await.unwrap();

    // Same (sandbox_id, host, port, binary) while pending -> upsert path:
    // hit_count accumulates and last_seen_ms advances; the original row id
    // is preserved.
    let mut second = draft_chunk("dc2", "sandbox-1", "api.example.com", 443, "/usr/bin/curl");
    second.hit_count = 1;
    second.last_seen_ms = 2000;
    store.put_draft_chunk(&second).await.unwrap();

    // The conflicting insert did not create a second row.
    let by_new_id = store.get_draft_chunk("dc2").await.unwrap();
    assert!(by_new_id.is_none());

    let updated = store.get_draft_chunk("dc1").await.unwrap().unwrap();
    assert_eq!(updated.hit_count, 2);
    assert_eq!(updated.last_seen_ms, 2000);
    // first_seen_ms is not modified by the upsert.
    assert_eq!(updated.first_seen_ms, 1000);

    let all = store.list_draft_chunks("sandbox-1", None).await.unwrap();
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn draft_chunk_list_with_status_filter() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_draft_chunk(&draft_chunk(
            "dc1",
            "sandbox-1",
            "a.example.com",
            443,
            "/bin/a",
        ))
        .await
        .unwrap();
    store
        .put_draft_chunk(&draft_chunk(
            "dc2",
            "sandbox-1",
            "b.example.com",
            443,
            "/bin/b",
        ))
        .await
        .unwrap();
    store
        .put_draft_chunk(&draft_chunk(
            "dc3",
            "sandbox-2",
            "c.example.com",
            443,
            "/bin/c",
        ))
        .await
        .unwrap();

    // No filter: only this sandbox's chunks.
    let all = store.list_draft_chunks("sandbox-1", None).await.unwrap();
    assert_eq!(all.len(), 2);

    // Approve one and filter by status.
    store
        .update_draft_chunk_status("dc1", "approved", Some(5000))
        .await
        .unwrap();

    let approved = store
        .list_draft_chunks("sandbox-1", Some("approved"))
        .await
        .unwrap();
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].id, "dc1");

    let pending = store
        .list_draft_chunks("sandbox-1", Some("pending"))
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "dc2");
}

#[tokio::test]
async fn draft_chunk_update_status() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_draft_chunk(&draft_chunk(
            "dc1",
            "sandbox-1",
            "a.example.com",
            443,
            "/bin/a",
        ))
        .await
        .unwrap();

    let updated = store
        .update_draft_chunk_status("dc1", "rejected", Some(7000))
        .await
        .unwrap();
    assert!(updated);

    let loaded = store.get_draft_chunk("dc1").await.unwrap().unwrap();
    assert_eq!(loaded.status, "rejected");
    assert_eq!(loaded.decided_at_ms, Some(7000));

    // Updating a non-existent chunk reports no rows affected.
    let missing = store
        .update_draft_chunk_status("no-such-id", "approved", Some(8000))
        .await
        .unwrap();
    assert!(!missing);
}

#[tokio::test]
async fn draft_chunk_update_rule_only_when_pending() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_draft_chunk(&draft_chunk(
            "dc1",
            "sandbox-1",
            "a.example.com",
            443,
            "/bin/a",
        ))
        .await
        .unwrap();

    // Pending -> rule update succeeds.
    let updated = store
        .update_draft_chunk_rule("dc1", b"new-rule-payload")
        .await
        .unwrap();
    assert!(updated);

    let loaded = store.get_draft_chunk("dc1").await.unwrap().unwrap();
    assert_eq!(loaded.proposed_rule, b"new-rule-payload");

    // Once approved, the rule is frozen: update reports no rows affected and
    // the payload is unchanged.
    store
        .update_draft_chunk_status("dc1", "approved", Some(9000))
        .await
        .unwrap();

    let frozen = store
        .update_draft_chunk_rule("dc1", b"should-not-apply")
        .await
        .unwrap();
    assert!(!frozen);

    let loaded = store.get_draft_chunk("dc1").await.unwrap().unwrap();
    assert_eq!(loaded.proposed_rule, b"new-rule-payload");
}

#[tokio::test]
async fn draft_chunk_delete_by_status() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store
        .put_draft_chunk(&draft_chunk(
            "dc1",
            "sandbox-1",
            "a.example.com",
            443,
            "/bin/a",
        ))
        .await
        .unwrap();
    store
        .put_draft_chunk(&draft_chunk(
            "dc2",
            "sandbox-1",
            "b.example.com",
            443,
            "/bin/b",
        ))
        .await
        .unwrap();

    // Reject one, leave the other pending.
    store
        .update_draft_chunk_status("dc1", "rejected", Some(1000))
        .await
        .unwrap();

    let deleted = store
        .delete_draft_chunks("sandbox-1", "rejected")
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(store.get_draft_chunk("dc1").await.unwrap().is_none());
    assert!(store.get_draft_chunk("dc2").await.unwrap().is_some());

    // Deleting a status with no matches affects zero rows.
    let none = store
        .delete_draft_chunks("sandbox-1", "approved")
        .await
        .unwrap();
    assert_eq!(none, 0);
}

#[tokio::test]
async fn draft_chunk_get_version() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    // No chunks yet -> version 0.
    assert_eq!(store.get_draft_version("sandbox-1").await.unwrap(), 0);

    let mut c1 = draft_chunk("dc1", "sandbox-1", "a.example.com", 443, "/bin/a");
    c1.draft_version = 3;
    store.put_draft_chunk(&c1).await.unwrap();

    let mut c2 = draft_chunk("dc2", "sandbox-1", "b.example.com", 443, "/bin/b");
    c2.draft_version = 7;
    store.put_draft_chunk(&c2).await.unwrap();

    // Max draft_version across this sandbox's chunks.
    assert_eq!(store.get_draft_version("sandbox-1").await.unwrap(), 7);

    // Unrelated sandbox is unaffected.
    assert_eq!(store.get_draft_version("sandbox-2").await.unwrap(), 0);
}
