# ADR 0002: User-code packaging and delivery (ADR 0001, gate 3)

- **Status:** implemented and security-reviewed as a prototype, 2026-11-22. **User code execution stays disabled**, in two independent places:
  - controller `user_code_enabled = false`, checked at dispatch and on every node package and blob endpoint;
  - agent `USER_CODE_ENABLED = False` (a constant, not configuration).

  Every finding of the adversarial review is fixed, each with a regression test that a targeted mutation shows to be effective. See [Review findings](#review-findings-2026-11-22). Gate 3's *design and delivery* part is therefore met, verified on one PC and in CI. It does **not** enable execution: that still needs ADR 0001 gate 2 and the prerequisites listed under "Before enabling user code".
- **Scope:** how researcher code, inputs and dependencies reach a lab PC, and how outputs come back.

## Decision

### 1. Format: a manifest plus content-addressed files, not an archive

**Structure.**
- A package is a canonical JSON manifest listing `{path, sha256, size}` for every file.
- Each file is uploaded separately as a blob named by its SHA-256.
- The package's identity is the SHA-256 of the canonical manifest.

**Why no archive.** With no archive to unpack, a whole class of attacks disappears:
- zip-slip;
- symlink or hardlink entries;
- duplicate entries;
- archive decompression bombs;
- format-parser bugs.

**Path rules** (`udcs_shared.packages.path_problem`):
- POSIX separators only;
- NFC-normalised;
- no absolute paths, drives or UNC paths;
- no `:` (NTFS alternate data streams);
- no `.`, `..` or empty segments;
- no control characters or `<>"|?*\`;
- no leading space or trailing dot/space;
- no reserved device names (CON, NUL, COM1-9 and so on, with or without an extension);
- at most 240 characters in total and 100 per segment.

**Structure rules:**
- files sorted (a deterministic structure, so the same content means the same digest);
- unique case-insensitively, as on Windows;
- no path that is both a file and a directory;
- extra fields forbidden;
- `schema_version` checked.

**Kinds.** `package` (user code, an entry script, optional environment and datasets), `environment` and `dataset`.

### 2. Dependencies: admin-approved, prebuilt, wheel-only environments

**What a package may declare:** exact pins only (`name==version`), and only satisfied by an **approved environment**.
- **What an environment is:** a content-addressed artifact of kind `environment`, with a lock, a Python version and a platform tag.
- **How it is built:** off the lab fleet, from wheels only (for example `pip install --only-binary :all: --require-hashes` on a build machine). An administrator reviews and approves it.

**On nodes:**
- **Nothing is ever installed or built on a node:** no pip, no `setup.py`, no build backends, no network access to PyPI. Workloads have no network at all (ADR 0001).
- **Shared runtime protected:** environments are staged read-only per job, so the shared UDCS runtime is never modified, and the existing runtime integrity check still repairs it on every launch.

**Rules enforced at registration:**
- the package's Python version (`3.12`) must equal the environment's;
- every pin must be present in the environment's lock;
- an environment must not contain `.pth` files (startup code hooks).

**Defence in depth:** isolated workloads run Python with `-I -S`, so `site`, `.pth`, `sitecustomize` and `usercustomize` are not processed anyway.

**Python version and native code:**
- **Python version:** an incompatible Python version is refused at registration.
- **Native code:** native dependencies exist only as prebuilt wheels for the environment's platform tag, reviewed with the environment.
- **Node fit:** whether a node's interpreter matches is a scheduling input still to be wired.

### 3. Limits are policy, not code

`PackagePolicy` is configured with `UDCS_PACKAGE_POLICY` (JSON). Its fields and defaults:

| Field | Default |
|---|---|
| Manifest | 2 MiB |
| Files | 10,000 |
| Per file | 256 MiB |
| Expanded package | 1 GiB |
| Transfer (compressed bytes) per session | 1 GiB |
| Dataset | 20 GiB |
| Environment | 4 GiB |
| Outputs | 2 GiB and 10,000 files |
| Output walk | 20,000 entries (files and directories), depth 32 |
| Runtime | 8 h |
| Config | 64 KiB |
| Chunk size | 8 MiB (64 KiB–64 MiB) |
| Compression ratio | ≤ 100× per chunk |
| Upload session lifetime | 24 h |
| Open uploads | 32 per owner |
| User storage quota | 50 GiB |

A package's own `limits` can only lower these.

Request bodies are bounded before they are buffered, by an ASGI middleware. A chunk `PUT` may carry at most `chunk_bytes`; any other request may carry at most max(4 MiB, manifest limit). The middleware checks the declared `Content-Length` and also counts the bytes that actually arrive, so chunked transfer encoding cannot get around it. (FastAPI reads a whole body before any handler or dependency runs, so the bound cannot live in a handler.)

### 4. Distribution: content-addressed, chunked, resumable, verified at every stage

**Upload.** `POST /blobs/uploads {sha256, size}` starts or resumes a session. Each chunk is `PUT ?offset=` with `X-UDCS-Chunk-SHA256`, and is accepted only if:
- it continues at the session's `received` offset (or retries the last chunk);
- it decodes within its declared raw size (zlib decoding is bounded: `max_length = raw + 1`, ratio ≤ policy);
- its decoded bytes match the chunk hash.

`complete` streams the whole partial file through SHA-256 and names the blob only on a match. If an upload is interrupted, the client asks `GET` for `received` and continues there. Measured: exactly the missing bytes are re-sent.

**Deduplication without an existence oracle.**
- *Storage* is deduplicated globally: one copy per digest.
- *Transfer* is skipped only for blobs **the caller already owns**. Anyone else must upload and so prove possession, and the bytes are then dropped as a duplicate. Knowing a hash never reveals whether another user has a file, and never grants it.
- On nodes, a local cache (`DATA_DIR/cas`) means each blob is fetched once per node, however many jobs use it.
- *Packages* follow the same rule. Identical content registered by two users is one package with two owners (`package_owners`), each having proven possession of every blob. Registering someone's content first therefore locks nobody out.

**Session hygiene.**
- Open sessions reserve their declared size against the user's quota.
- The quota is re-checked when an upload completes.
- Every upload start sweeps up to 200 dead sessions (expired, or node sessions whose attempt is no longer current), marks them `expired` and deletes their partial files.
- Zero-byte files (an empty `__init__.py`) are ordinary blobs.

**Node downloads.**
- They are fenced: a node may fetch a blob only while it holds the current attempt of a job whose manifest closure contains that blob.
- They use `Range` resume, and the full SHA-256 is checked before a blob enters the cache.

**No execution before full verification.** Staging copies every file from the cache while re-hashing it, so a cache file modified after download fails staging.

### 5. Node staging

**Layout.** `DATA_DIR/staging/<job>-<attempt>/`, fresh for each attempt (a stale attempt never shares files with the current one):
- `src/` and `env/`;
- `inputs/<name>/`;
- `config.json`;
- `out/`.

**Protection.**
- The directory inherits the protected data-directory ACL (SYSTEM and Administrators).
- Files are marked read-only.
- The path is re-checked against the root after resolution, and any reparse point in the tree fails staging.

**Grants.** For the future execution step, the AppContainer gets read/execute on `src`, `env`, `inputs` and `config` only, and modify on `out` only (`StagedJob.read_only`, `StagedJob.output`), through the ADR 0001 adapter.

**Cleanup.** `remove_staging` deletes read-only trees and never follows a junction out of the tree. It is tested with a junction pointing at a "student" directory, which survives.

### 6. Results

**Collection.** `collect_outputs` runs only after the job's process tree has been terminated. It does not rely on that alone:
- **Handle, not path.** Each file is opened first (`FILE_FLAG_OPEN_REPARSE_POINT`; `O_NOFOLLOW` elsewhere), and the *open handle* must be a regular file with exactly one link whose final path (`GetFinalPathNameByHandleW`) lies inside `out/`. A junction swapped in after a path check, or a hard link to a file elsewhere on the volume, is refused, never followed.
- **One read.** The bytes hashed are the bytes copied from that handle into an agent-private snapshot (`staging/<job>-<attempt>/collected/`, with no sandbox grant). The upload reads the snapshot, never `out/` again.
- **Bounded walk.** Files, bytes, walked entries (directories included) and depth are all counted *while walking*, so a hostile tree cannot make collection unbounded.

**Upload and report.**
- Outputs are uploaded with the same chunked protocol, as node uploads tied to the job and attempt.
- Node uploads are bounded per attempt when each session starts: open plus completed sessions count against the package's and the policy's output limits. They are accepted only while that attempt is the job's current, active one.
- Outputs are reported with `PUT /agent/jobs/{id}/outputs`, once per attempt. Each file must have been **uploaded in full by this node for this attempt**, or be a blob the job owner already holds. Naming a hash is never enough, since that would let a node hand the job owner any blob in the store. "Missing" and "not uploaded here" give the same error, so this is no existence oracle either.

**Retrieval.** The job owner then owns the output blobs and can download them with Range. Nothing is loaded wholly into memory at any stage.

**Cleanup.** `remove_staging` never changes a file's attributes. Read-only files are deleted with `FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE`, because clearing the attribute with `chmod` would change it on every other name of a hard-linked file.

**Unchanged:** checkpoints, fencing and result verification of catalog jobs.

## Measured (2026-11-22, loopback TLS, i5-6500; `docs/acceptance/data/m2-transfer-benchmark.json`)

Re-measured after the review fixes:

| Measurement | Result |
|---|---|
| Upload, 64 MiB incompressible | 15.2 MiB/s (wire 1.00×) |
| Upload, 64 MiB compressible CSV | 15.7 MiB/s; **wire 0.117×** |
| Re-upload of owned content | skipped (0.2 s; hashing only) |
| Resume after a crash at 24 MiB | 40 MiB re-sent (exactly the remainder) in 1.1 s |
| Download with SHA-256 verification | 94.6 MiB/s |
| Download resume with half present | fetched exactly the missing 32 MiB |
| 200 small files | 13.5 files/s: **weak**, three round trips, an fsync and a sweep query per file |
| Staging 200 files, re-verifying every byte | 0.48 s |
| Storage overhead | blob store 192.39 MiB for 192.78 MiB logical; manifest ~111 B per file; database 0.42 MiB |

Notes:
- Uncompressed upload ran at about 36 MiB/s (the resume run), so zlib level 6 costs CPU. Use a cheaper level, or sample compressibility, before production.
- A batch upload endpoint is needed for many small files.
- Loopback on one PC measures UDCS's own overhead, not a campus network.

## Review findings (2026-11-22)

Adversarial review in three lenses: transfer and CAS; staging and outputs; dependencies, substitution and policy. All findings were verified against the code and fixed. Each fix has a regression test. A mutation that removes the fix makes its test fail: 13 of 13 caught.

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| F1 | **high** | An output manifest gave the job owner ownership of *any* blob named by hash, including other users' private blobs. It was also an existence and size oracle, and repeatable | An output counts only if this node uploaded it completely for this attempt, or the owner already holds it. One error for both cases. One manifest per attempt | `test_outputs_cannot_claim_another_users_blob` |
| F2 | medium | Node uploads had no total bound and stayed open after the job ended | Per-attempt output budget at session start; uploads only while the attempt is current and active; stale sessions swept | `test_node_uploads_are_bounded_per_attempt_and_fenced` |
| F3 | medium | A chunk body was read fully into memory before any size check | Body-limit middleware (declared length plus counted bytes) for chunks and JSON | `test_oversized_request_bodies_are_refused_before_buffering` |
| F4 | medium | Expired or abandoned sessions left partial files forever; the quota ignored open sessions | Sweep on every upload start; open sessions reserve quota; quota re-checked at completion | `test_abandoned_sessions_are_swept_and_reserve_quota` |
| F5 | medium | `collect_outputs` checked a path and then reopened it (TOCTOU): a junction swapped in later was followed | Open first, check the handle's type, link count and final path; hash and copy from that handle into a private snapshot | `test_outputs_check_the_open_handle_not_the_path`, `test_outputs_are_copied_privately_and_hash_what_was_copied` |
| F6 | medium | Hard links in `out/` were accepted (exfiltration), and `remove_staging` cleared read-only on link targets | Link count must be 1; deletion never chmods | `test_outputs_refuse_hard_links`, `test_cleanup_never_changes_a_hard_link_target` |
| F7 | medium | The controller kill switch was not checked at dispatch or on node endpoints; a node could claim `user_code` itself | Dispatch needs the controller flag *and* the node flag; every node package and blob endpoint returns 404 while off | `test_kill_switch_stops_dispatch_and_node_endpoints` |
| F8 | low | The output walk had no bound on directories, entries or depth | `max_output_entries`, `max_output_depth`, counted while walking | `test_output_walk_is_bounded_in_entries_and_depth` |
| F9 | low | Registering identical content returned another user's package, locking the second user out (and revealing that it existed) | `package_owners` table | `test_identical_content_registered_by_two_users_is_usable_by_both` |
| F10 | low | Zero-byte files failed at completion (500) | An empty partial file is created and its hash checked | `test_zero_byte_files_upload_and_register` |
| F11 | low | Node upload resume ignored the attempt, so a new attempt resumed a stale session | Resume and budget are keyed by (node, job, attempt) | covered by F2's test |

## Before enabling user code (beyond ADR 0001 gate 2)

1. **Per-node eligibility set by an administrator on the controller.** The controller flag is global, and the node's `user_code` capacity is self-reported. Neither is a fleet policy.
2. **Termination before collection.** The execution step must kill the job object before `collect_outputs` runs, and revoke the sandbox's grant on `out/`. Collection is safe without that (handle checks), but outputs could still change mid-copy.
3. **Charging outputs to quotas.** Output blobs count against the job owner's storage once granted. They are bounded by the output limits, but are not refused at the quota.

## Not done (honest)

- **Execution of user code.** Disabled by design until ADR 0001 gate 2 (a review of what a lab image exposes to ALL APPLICATION PACKAGES) passes.
- **Node Python version and environment matching** in the scheduler.
- **Garbage collection of unreferenced blobs.** Dead upload sessions are swept, but blobs that no owner, package or job references are kept.
- **A periodic sweep.** The session sweep runs lazily, when uploads start, not on a timer.
- **Per-lab or per-group dataset access control.** Approved datasets are currently usable by any user.
- **Chunked checkpoints** over 1 MiB (deferred earlier).
- **A standalone client tool:** the uploader currently lives in the agent package.
- **Integrity against a dishonest node:** reported outputs are hashed, but a node can fabricate them (T26).

## Researcher client (`udcs`), 2026-11-23

**Guide:** [docs/guides/researcher-client.md](../guides/researcher-client.md). Execution **remains disabled**. The client never works around that:
- while `GET /deployment` reports `user_code_enabled: false`, `udcs submit` uploads and registers the package (the controller validates it), prints that **no job was created**, exits 3, and sends no `POST /jobs`;
- there is no client flag, environment variable or "pending" state that changes this.

**Design.** Three independent designs (security-first, researcher-first, minimal) were judged against the code and combined. The judge caught real errors before any code was written, for example that the agent's DPAPI was machine-scoped, so a researcher token stored with it would be readable by every account on a shared PC.

**Layout:**
- `client/` (package `udcs-client`, script `udcs`) depends only on `udcs-shared[http]`.
- The transfer primitives moved out of the agent into `udcs_shared.transfer` (stdlib) and `udcs_shared.transfer_http` (the optional `http` extra), so the client does not pull in agent dependencies (psutil, pywin32, NVML). The agent re-exports them, and its `_is_reparse` test seam is kept.
- `udcs_shared.dpapi` gained a scope (`machine` for the node credential, unchanged; `user` for researcher sessions) and per-purpose entropy.

**Controller additions** (all additive, all behind `SubmitJobs`):
- `GET /packages?kind=environment|dataset`: approved items only; user packages are never listed.
- `GET /deployment`.
- `JobOut.package`.
- A log cursor, `GET /jobs/{id}/logs?after=`. Before it, a client could never see past the first 200 lines.
- `OutputManifest` now also refuses file/directory clashes.

**Security properties, each tested:**

| Area | Property |
|---|---|
| File selection | An include allowlist, plus a hard deny list: VCS, caches, venvs, results, and about 40 credential file shapes. Naming a denied file is an error. Links and junctions are refused. A secret heuristic, labelled as one |
| Credentials | DPAPI user scope (Windows) or 0600 (POSIX). The token is bound to its origin, which is normalised. `UDCS_TOKEN` must be bound to `UDCS_SERVER`. No redirects. https only. `logout` revokes at the issuing origin and says when it could not |
| Fetch | Model-validated paths. Directories are created one segment at a time with link checks, plus a resolved-path check. Downloads are hash-verified, more bytes than declared are refused, and nothing is ever overwritten. Reserved names are refused. `--resume` is bound to the job, attempt and output set. A client-side byte limit and a free-space check apply |
| Output | All server text is sanitised: escapes and control characters are stripped, then secrets are redacted, then the text is cut |

**Review.** A five-lens adversarial review confirmed 27 findings, with each one independently verified; none were rejected:

| Severity | Count | Examples |
|---|---|---|
| Medium | 11 | logout not revoking the stored token; outputs colliding with the client's reserved names; `--resume` mixing fetches; config values lost on rewrite; gaps in the deny list; `dataset push` uploading before policy checks; `watch` dropping the final log lines |
| Low | 16 | `UDCS_TOKEN` not origin-bound; `:443` origin mismatch; redaction order; CA bundle errors; job ids used as paths |

All 27 are fixed with regression tests (`client/tests/test_client_review_regressions.py`). A mutation pass removed 15 security guards one at a time: 14 are caught, and the file-symlink guard's test is skipped on machines that cannot create symlinks.

**Bugs found while building it:**
- A zero-byte blob could never be downloaded, which also affected the agent's `fetch_blob`.
- The e2e controller fixture wrote blobs into the repository's `var/`.

**Open decisions and limits:**
- ~~Package jobs still carry the catalog contract.~~ **Resolved by [ADR 0003](0003-package-execution.md):** package jobs have their own contract (exit code, output digest, failure class, run limits).
- **The package-job end-to-end path is untested.** Nothing executes yet. A skipped test, `test_package_job_end_to_end`, keeps it visible.
- **Many small files remain slow** (about 13 files/s); the client warns above 1,000 files.
- **The secret heuristic is not exhaustive.** The allowlist is the control.

