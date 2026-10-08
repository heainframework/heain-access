# heain-access

Standalone access-control service for the HEAIN Core Protocol ecosystem.
Issues and verifies `AccessGrant`s via pluggable `Verifier` implementations
(ID card, face, fingerprint, keycard, DCP/KDM key issuance).

Called directly by other Layer 3 modules (e.g. heain-mastering at DCP-build
time) — not registered into heain-job's data-type strategy/registry-pool.

## heain-access v2 — rebuilt on heain-sdk v1 (Step 4d, 2026-10-06)

**The text above describes the Stage A version, kept as tag `legacy-v0`.** That version served plain HTTP, kept grants in memory, took the enrolled image from the caller on every check, and its keycard ACL was a flag. v2 runs through heain-core.

**Author decisions (2026-10-06):** templates only, never images (data class `biometric_template`: `raw_storage: forbidden`, retention max 30 days, crypto-shred); the AI models stay Python sidecars (`ai_sidecars`, contract heain-sidecar/v1, localhost only); keycard ACLs and reference registries live in heain-database; `dcp-key` is an optional plugin.

| Capability (lane) | Endpoint | |
|---|---|---|
| `identity.enroll.face` / `.fingerprint` (identity, AI) | `POST /v1/enroll/face` · `/v1/enroll/fingerprint` `{"subject","image_b64"}` | the sidecar reduces the image to an embedding / minutiae template; only that is kept, sealed under a per-subject data key in core's KMS |
| `identity.subject.remove` (identity) | `DELETE /v1/subjects/{subject}` | deletes the templates and destroys the subject key (crypto-shred) |
| `identity.verify.face` / `.fingerprint` (identity, AI) | `POST /v1/verify/face` · `/v1/verify/fingerprint` `{"subject","image_b64"}` | cosine similarity ≥ `-face-threshold` (0.5) / match score ≥ `-fingerprint-threshold` (0.8) |
| `identity.verify.idcard` (identity, AI) | `POST /v1/verify/id-card` `{"image_b64","expected_id_number","registry":{"dataset","scope_key"}}` | OCR must read the number; with `registry`, heain-database must list it and not as `"eligible": false` |
| `identity.verify.keycard` (identity) | `POST /v1/verify/keycard` `{"uid","acl":{"dataset","scope_key"}}` | allowed when heain-database lists the uid and not as `"allowed": false` (default ACL: `-keycard-acl-dataset keycards`, `-keycard-acl-scope default`) |
| `access.grant.issue` | `POST /v1/grants` `{"recipient","asset_ref","valid_from","valid_until","verification_id"}` | needs a successful verification from the last 10 minutes, used once; the grant is signed with the app key |
| `access.grant.check` / `.revoke` | `GET /v1/grants/{id}` · `POST /v1/grants/{id}/check {"asset_ref"}` · `DELETE /v1/grants/{id}` | check verifies the signature, the asset, the window and revocation |
| `access.kdm.issue` (plugin `dcp-key`) | `POST /v1/plugins/dcp-key/kdm` `{"evidence":{…}}` | the Stage A KDM issuance, enabled with `-dcp-key-ca-file`, `-dcp-key-issuer-cert-file`, `-dcp-key-issuer-key-file`; else 501 |

Every face, fingerprint and ID-card decision (and enrolment) files a signed AI reasoning record with the model hash the sidecar reports on `GET /info`. Calls to `identity.*` carry `X-Heain-Lane: identity`. Subject ids are stored only as HMACs; grants and the subject index are sealed under the app's data key `inside`.

**Sidecars** (`sidecars/`, each binds 127.0.0.1): OCR `:9700` (`/extract`), face `:9701` (`/embed`), fingerprint `:9702` (`/template`, `/match_template` — templates instead of images since v2). Each also answers `GET /info`. Run them however you like; `-test-stub-sidecars` (TEST ONLY) replaces all three with deterministic model-free stand-ins.

Tests: `go test ./...`; live `bash scripts/live_4d.sh` (needs `~/heain-core`, `~/heain-sdk`, `~/heain-database`; stub sidecars); conformance `heain-conformance run --app .` (heain-database as companion).

**Not yet:** a live run with the real models on fresh test images; the keycard anomaly model; full DCI/SMPTE KDM XML.

**Step 4j (2026-10-06): the dcp-key plugin issues real SMPTE KDMs.** `POST /v1/plugins/dcp-key/kdm` now takes
`{"target_certificate_pem", "cpl_id", "content_title_text", "not_valid_before", "not_valid_after", "keys":[{"type":"MDIK|MDAK|…","id","key_hex"}], "content_authenticator"?, "annotation_text"?, "device_list"?: "assume_trust"|"recipient"}`
(the earlier `{"evidence":{…}}` body is gone) and answers `{"issued": true, "kdm_xml", "message_id", "recipient"}` or
`{"issued": false, "reason"}`. The KDM is an SMPTE ST 430-1 KDM in the ST 430-3 envelope: one RSA-OAEP (SHA-1, MGF1)
138-byte cipher block per content key to the target certificate, which must chain to `-dcp-key-ca-file` (intermediates
may follow the leaf); signed with XML Signature (RSA-SHA256) by `-dcp-key-issuer-cert-file` (a chain, leaf first).
Only the apps in `-dcp-key-callers` (default `heain-mastering`) may ask: the plugin signs whatever keys it is given, and
heain-mastering asks only after an Approver has approved the request through P5. `internal/xmldsig` is the shared
canonical-XML writer and signer (the same file is in heain-mastering).

## Stage B-3a: the keycard anomaly signal (2.2, 2026-10-08)

The author decided (2026-10-08) to build the keycard anomaly model in Go. This closes "the keycard anomaly model" in "Not yet" above; a live run with the real models on fresh test images is still to come.

- **The ACL decides, as before.** A card not on it is denied, and the model never changes the decision.
- **Each swipe** (`POST /v1/verify/keycard` `{"uid","reader"?,"at"?}`) is described against that card's earlier swipes: hours from any earlier time of day, how new the weekday and the reader are for the card, the gap since its last swipe, swipes in the last ten minutes, denials in the last day.
- **An Isolation Forest** fitted on the recent swipes of every card scores it. The forest needs 50 swipes in all, a card 10 (`-keycard-min-history`); before that the answer is `insufficient_history`.
- **At `-keycard-anomaly-threshold` (0.65) or above** the swipe is flagged and goes to an Approver as P5 `access.keycard_review` (THRESHOLD_BASED). It is still allowed when the card is on the ACL. The answer carries `anomaly` (status, score, features, history) and `review_action_id`.
- **Every keycard decision** files a signed reasoning record (model `keycard-iforest`, role advisory). The input is the card's HMAC, never its id.
- **History:** swipes are kept sealed per card under an HMAC of its id, for at most `-keycard-history-retention` (90 days; data class `keycard_history`). A reader that uploads its log late sends each swipe's own time as `at`.
