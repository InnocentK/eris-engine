# Invariants - do-not-break rules and the tests that enforce them

Read the relevant section before editing a subsystem. Each rule names its
test; if you must change a rule, change its test in the same commit and add a
CHANGELOG entry.

## Hermeticity (`tests/conftest.py`)
| Rule | Test |
|---|---|
| `shutil.which` returns None for worker binaries in every test | `test_hermeticity.py::test_which_hides_worker_binaries` |
| Every subprocess entry point raises `HermeticityViolation` | `test_hermeticity.py::test_subprocess_entry_points_raise` |
| Sockets cannot connect, bind or resolve; httpx is blocked | `test_hermeticity.py::test_sockets_cannot_connect_or_resolve`, `::test_httpx_is_blocked_at_the_socket` |
| `real_subprocess` releases only `sys.executable`/`sleep` (+ explicit `allow`); never `shell=True` | `test_hermeticity.py::test_marker_releases_only_sys_executable_and_sleep`, `::test_marker_allow_extends_the_list` |
| Production code resolves `shutil.which` at call time, never as a default argument | `test_hermeticity.py::test_guard_reaches_call_time_which_lookups` |
| `agy` is a guarded worker binary (`gemini` stays in the set) | `test_hermeticity.py::test_agy_is_a_guarded_worker_binary` |

## Fixtures (`tests/fixtures/`)
| Rule | Test |
|---|---|
| No file under `tests/fixtures` (name or body) contains a user path: any `/Users/<name>` or `/home/<name>` with `<name>` not a placeholder (`USER`/`user`), or any `/private/tmp/claude-*/-Users-*` session path, fails (portable pattern scan; no username literal in the repository); the `/Users/USER` and `/private/tmp/OUTSIDE` placeholders are present. Additional local check: the account running the suite is absent too (skipped when it cannot be determined) | `test_fixtures.py::test_no_fixture_contains_a_user_path`, `::test_no_fixture_contains_the_local_user` |
| Every captured envelope has a `.meta.json` sidecar whose argv is either mechanically recorded by a battery script (`scratchpad/exp2/run.sh` or `scratchpad/flagtest/claude_tests.sh`) or explicitly labelled `argv_source: reconstructed by the synthesizer …; not mechanically captured` (A7/A8/A10b/A14/A15/A16 and E17 are reconstructed); agy sidecars list flags in the canonical builder order and say when a run had no `--add-dir`. M2b captures: `claude/2.1.239/budget_tripped.json` (T2), `codex/0.147.0/auth_401.jsonl` (E2), `grok/1.0.5/api_error_403.json` (E17) | `test_fixtures.py::test_every_capture_has_a_meta_sidecar_with_argv`, `::test_agy_sidecars_state_the_canonical_argv_order` |

Exception (stated in AGENTS.md as well): the marker accepts `allow=["git"]`
and its single call site is `test_snapshot.py::test_snapshot_has_no_future`
(plus `test_hermeticity.py::test_marker_allow_extends_the_list`, which proves
the allow list is honoured). No other test may spawn `git`.

## Schemas (`src/eris/schemas.py`)
| Rule | Test |
|---|---|
| Canonical bytes of every record type are pinned per `SCHEMA_VERSION` | `test_schemas.py::test_golden_bytes_pinned`, `::test_every_record_type_has_a_golden_file` |
| Committed goldens are IMMUTABLE (`tests/fixtures/records/MANIFEST.json` pins every file of every version); any serialization change = new `SCHEMA_VERSION` dir + manifest entry, and bump `eris.version` + CHANGELOG in the same commit | `test_schemas.py::test_committed_goldens_are_immutable`, `::test_current_schema_version_has_a_manifest_entry` |
| Records from any other `schema_version` are refused at parse time (no 0.x migrations) | `test_schemas.py::test_old_schema_versions_are_rejected_on_parse` |
| EVERY committed golden directory (0.1.0, 0.1.1, 0.1.2 and the current 0.1.3) AND its manifest block are byte-identical to what was committed (block hashes pinned as constants in the test; committed = immutable; the next serialization change goes to 0.1.4 with a new constant). Editing a current golden, or its manifest line to match, fails | `test_schemas.py::test_committed_goldens_are_byte_identical_to_their_pinned_manifest`, `::test_editing_a_current_golden_or_its_manifest_line_fails_without_a_bump` |
| 0.1.2: `Invocation.conversation_id` / `worker_reported_duration_ms` are optional (default None, `>= 0`); `duration_ms` stays Eris's clock figure | `test_schemas.py::test_invocation_0_1_2_fields`, `test_launch.py::test_run_worker_agy_success_threads_conversation_and_duration`, `test_run_hermetic.py::test_invoke_agy_persists_conversation_id_and_worker_duration` |
| 0.1.3: `Invocation.{prompt_sha256, reused_from, pgid, warning}`, `CostRecord.{estimated, cost_known}`, `Proposal.evidence_requests`, `Adjudication.evidence_requests`, `EvidenceRequest.expect_exit_code` are optional additions absent from the 0.1.2 goldens; the five new records `EvidencePack`, `RetryAttempt`, `ScanResult` (hashes + counts only, no text field), `SnapshotSanitization`, `ArmRun` are `mechanically_observed`, in `RECORD_TYPES` and golden-pinned; `Stage` is `propose, critique, verify, adjudicate, summarize` | `test_schemas.py::test_schema_0_1_3_field_additions`, `::test_schema_0_1_3_new_records_are_golden_pinned_and_observed`, `::test_stage_has_verify_and_summarize` |
| Every record carries `origin` and `schema_version`; extras forbidden; frozen | `test_schemas.py::test_every_record_carries_origin_and_schema_version`, `::test_extra_fields_are_forbidden`, `::test_records_are_frozen`, `::test_record_base_requires_origin` |
| Timestamps are RFC 3339 `Z`; NaN refused | `test_schemas.py::test_timestamps_must_be_rfc3339_z`, `::test_canonical_bytes_refuse_nan` |
| `dissent`/`residual_risks` are required keys but may be empty | `test_schemas.py::test_adjudication_allows_empty_dissent_and_risks` |

## Validator (`src/eris/validate.py`) - pure, never raises
| Rule | Test |
|---|---|
| Missing / model_asserted / stale (verification-phase only) refs downgrade | `test_validate.py::test_ref_missing_downgrades`, `::test_ref_model_asserted_downgrades`, `::test_ref_predates_claim_only_for_verification_phase`, `::test_evidence_pack_item_may_predate_claim` |
| SUPPORTED/REFUTED without refs downgrade | `test_validate.py::test_supported_without_refs`, `::test_refuted_without_refs` |
| >= 3 cumulative downgrades force ESCALATE; 2 do not | `test_validate.py::test_escalates_at_three_downgrades`, `::test_two_downgrades_do_not_escalate`, `::test_downgrades_accumulate_across_passes` |
| `enforce_rulings` is idempotent and never raises | `test_validate.py::test_enforce_is_idempotent`, `::test_property_enforce_never_raises_and_is_idempotent` |
| Contest with empty dissent / ACCEPT with empty risks are errors; ABSTAIN with empty lists is clean | `test_validate.py::test_dissent_empty_with_contest_from_ruling`, `::test_dissent_empty_with_contest_from_challenge`, `::test_residual_risks_empty_on_accept`, `::test_abstain_with_empty_lists_is_honest_and_clean` |
| Origin rules per record type and evidence kind | `test_validate.py::test_origin_mismatch_cases` |
| Unevidenced challenges are retained as warnings | `test_validate.py::test_unverified_challenge_is_warning_and_retained` |
| Ledger chain: SEQ_GAP, HASH_MISMATCH, SCHEMA_VERSION, MALFORMED_LINE; never raises | `test_validate.py::test_events_*`, `::test_property_validate_events_never_raises` |

## Policy (`src/eris/policy.py`) - fail closed
| Rule | Test |
|---|---|
| `executable_sha256`, `timeout_s`, `max_stdout_bytes`, `vendors_allowed` required; unknown keys refused | `test_policy.py::test_missing_required_worker_field_refuses`, `::test_missing_vendors_allowed_refuses`, `::test_unknown_key_refuses` |
| `timeout_s` (strict int in `[1, 86400]`), `max_stdout_bytes`, `max_stderr_bytes` (strict ints `> 0`): no `"60"`/`60.0`/`true` coercion | `test_policy.py::test_worker_int_limits_are_strict` |
| `trusted` defaults to False | `test_policy.py::test_repo_default_policy_loads_and_is_untrusted_and_unpinned` |
| Secret-shaped value in policy or pins refuses the load | `test_policy.py::test_secret_shaped_value_refuses_load`, `::test_secret_in_pins_file_refuses` |
| API hosts allowlisted; https only except loopback | `test_policy.py::test_api_worker_host_and_scheme_rules` |
| `CliName` is claude/codex/agy/grok: `cli: gemini` is refused | `test_policy.py::test_gemini_cli_is_no_longer_a_valid_cli_name`, `test_no_gemini.py::test_no_gemini_builder_parser_or_cli_name` |
| Lineage guard (SYNTACTIC only): an `agy` worker must declare a model matching `^gemini-\S+$` — bare `gemini-`, ` gemini-x`, `GEMINI-x`, `xgemini-y`, `""`, None refused (agy also serves other vendors' ids and may silently default; the executed model is unobservable); the repo policy's agy entry is google / gemini-* / `AGY_CLI_DISABLE_AUTO_UPDATE` and declares `~/.gemini/antigravity-cli/settings.json` | `test_policy.py::test_agy_lineage_guard_refuses_non_gemini_models`, `::test_agy_lineage_guard_accepts_gemini_ids`, `::test_agy_loads_with_a_gemini_model`, `::test_repo_default_policy_agy_entry` |
| Provider must be in `vendors_allowed` | `test_policy.py::test_provider_not_in_vendors_refuses` |
| M2b: `cache_dir` (never equal to or under `runs_dir`), `WorkerPolicy.{sanitize_snapshot, role_tools}` (role keys validated; `tools_for_role`), `budgets.per_campaign_usd`, `verify.{max_requests_per_run, max_wall_s}` (strict ints), `sanitize.{strip_names, strip_dirs}` ADD to the enforced R3.1 minimum (`SANITIZE_MIN_NAMES`/`DIRS`), `scan.patterns_from_policy`, `containment` (`null` or `container`); the repo policy declares `judge` (claude, `tools: []`, timeout 300) and `sanitize_snapshot: true` for agy and grok | `test_policy.py::test_repo_default_policy_m2b_fields`, `::test_sanitize_policy_adds_but_never_removes_the_minimum`, `::test_cache_dir_must_not_be_under_runs`, `::test_role_tools_keys_are_validated_and_override_tools`, `::test_verify_caps_and_campaign_budget_are_strict`, `::test_repo_default_policy_loads_and_is_untrusted_and_unpinned` |
| `eris policy pin` uses only `which` + hashlib; missing executable is a recorded absence | `test_policy.py::test_pin_executables_hermetic`, `::test_pin_missing_executable_is_recorded_absence` |

## Redaction (`src/eris/redact.py`)
| Rule | Test |
|---|---|
| Every pattern redacts with `[REDACTED:<id>#<n>]` and counts | `test_redact.py::test_each_pattern_redacts_with_placeholder_and_count`, `::test_value_group_patterns_keep_the_key_name` |
| Placeholders carry no fingerprint of the secret | `test_redact.py::test_no_fingerprint_in_placeholder` |
| Split across chunks, newline-wrapped, ANSI-interleaved, base64 (std/urlsafe/wrapped) are caught | `test_redact.py::test_split_across_chunks`, `::test_newline_wrapped_secret_is_redacted_without_eating_the_newline`, `::test_ansi_interleaved_secret`, `::test_base64_encoded_secret_is_redacted_whole_run` |
| A secret at end of line does not swallow the next line | `test_redact.py::test_secret_at_end_of_line_keeps_following_text` |
| Exact values (>= 8 chars, regex-safe) are redacted | `test_redact.py::test_exact_values_are_redacted_and_short_ones_ignored`, `::test_exact_value_with_regex_metacharacters` |
| 50 MB buffers are handled | `test_redact.py::test_fifty_megabytes_with_sprinkled_secrets` |

## Writer (`src/eris/writer.py`) - the only path to `runs/`
| Rule | Test |
|---|---|
| seq/prev_sha256/payload_sha256 chain validates | `test_writer.py::test_seq_and_prev_sha_chain_validate` |
| fsync on every durable write (events, blob, blob dir, manifest, run dir) | `test_writer.py::test_fsync_is_called_for_every_durable_write` |
| Blobs are redacted before hashing; temp+rename; no temp left | `test_writer.py::test_put_blob_is_redacted_before_hashing_and_atomic` |
| A write failure raises and leaves no partial blob or manifest | `test_writer.py::test_write_failure_raises_and_leaves_no_partial_blob` |
| Manifest written last; writer closed afterwards | `test_writer.py::test_finalize_writes_manifest_last_and_closes` |
| One writer per run dir (in-process and across processes) | `test_writer.py::test_lock_is_single_writer_in_process`, `::test_lock_is_single_writer_across_processes` |
| Only a non-newline-terminated partial tail is recoverable (on resume); a complete invalid line ANYWHERE, including last, is INVALID | `test_writer.py::test_torn_tail_truncated_only_on_resume`, `::test_complete_but_unparsable_last_line_is_invalid_not_torn`, `::test_malformed_middle_line_is_invalid` |
| Directory entries are fsynced at creation (runs parent, run dir, blobs dir, after .lock/events exist) | `test_writer.py::test_fsync_is_called_for_every_durable_write` |
| On resume every blob is re-hashed: one whose bytes do not hash to its name, or a symlink, is listed in `corrupt_blobs` and NOT indexed (a fresh `put_blob` rewrites it); `blob_intact(sha)` is the resume gate (F5); `on_event` is an observer, never a second writer | `test_writer.py::test_resume_rehashes_blobs_and_refuses_a_tampered_or_symlinked_one` |
| No secret anywhere on disk (plain, ANSI-split, base64, payload, manifest extra) | `test_writer.py::test_no_secret_anywhere_on_disk`, `test_run_hermetic.py::test_invoke_full_path_is_hermetic_and_redacted` |

## Launcher (`src/eris/launch.py`)
| Rule | Test |
|---|---|
| argv per CLI exactly as specified | `test_launch.py::test_claude_argv_exactly_as_specified`, `::test_codex_argv_exactly_as_specified`, `::test_agy_argv_exactly_as_specified`, `::test_grok_argv_exactly_as_specified` |
| The agy builder never emits `-c`, `--continue`, `--conversation`, accept-edits or `--dangerously-skip-permissions` (exact-element check; `-c` is deliberately not a substring token) | `test_launch.py::test_agy_argv_never_contains_continue_or_edit_flags` |
| agy `--add-dir` is REQUIRED, appears exactly once (outside the prompt) and equals the spawn cwd's realpath (A14: no workspace → agy cannot read its own cwd; A16: with it, reads outside are denied); `plan_call` re-checks element by element and refuses a second, missing or different workspace; the harness records the same path on the Invocation | `test_launch.py::test_agy_add_dir_is_the_workspace_realpath_exactly_once`, `::test_plan_call_agy_refuses_a_tampered_workspace`, `::test_plan_call_per_cli`, `::test_run_worker_agy_success_threads_conversation_and_duration`, `test_run_hermetic.py::test_invoke_agy_persists_conversation_id_and_worker_duration` |
| The `--add-dir` battery fixtures parse (A14 denied inside without workspace; A15 SUCCESS with the injected `MANGO KIWI` prefix on record; A16 denied outside with workspace, no canary) | `test_launch.py::test_parse_agy_add_dir_battery_fixtures` |
| agy `--print-timeout` = `timeout_s - 30` above 60 s else `max(1, timeout_s // 2)`, ALWAYS strictly below `timeout_s` (boundary values 1, 2, 30, 31, 60, 61, 86400); `timeout_s < 2` is refused for agy; rendered `<N>s` after `--disable-slash-commands` (canonical order: `-p … --model … --mode plan --sandbox --add-dir … --output-format json --disable-slash-commands --print-timeout Ns [--json-schema …]`) | `test_launch.py::test_agy_print_timeout_derivation`, `::test_agy_print_timeout_is_strictly_before_eris_timeout`, `::test_run_worker_agy_refuses_one_second_timeout`, `::test_plan_call_agy_print_timeout_tracks_policy_timeout`, `::test_agy_argv_exactly_as_specified` |
| `worker_reported_duration_ms` accepts only finite `duration_seconds` in `[0, 1e7]` (Infinity/NaN/1e309/huge ints/negatives/strings → None, never an exception); a parser exception is contained in `_execute` → FAILED `<cli>: parser failure: …` (`run_worker` never raises) | `test_launch.py::test_parse_agy_duration_is_contained`, `::test_run_worker_never_raises_on_a_parser_bug` |
| Forbidden tokens (incl. the agy additions) refused in every argv element EXCEPT the prompt (which may quote them); prompts starting with `-` refused | `test_launch.py::test_forbidden_tokens_are_refused_outside_the_prompt`, `::test_argv_hygiene` |
| NEVER list includes the Google/Antigravity credential names and the `ANTIGRAVITY_` prefix; `AGY_` is not blanket-banned; agy's env carries `AGY_CLI_DISABLE_AUTO_UPDATE=1` | `test_launch.py::test_never_list_names_are_refused`, `::test_agy_env_disables_auto_update_and_agy_prefix_is_not_banned` |
| `parse_agy` matches every captured agy 1.1.18 fixture: `status != SUCCESS` → `is_error` with `agy: <error>`, usage RETAINED on error, empty response → `text None`, `structured_output` preferred (any shape, extra keys kept), no model id / cost, `conversation_id` + `duration_seconds` captured | `test_launch.py::test_parse_agy_plain_fixture`, `::test_parse_agy_schema_fixture_structured_output_is_exact`, `::test_parse_agy_error_fixtures_retain_usage`, `::test_parse_agy_auth_failed_has_no_conversation`, `::test_parse_agy_bad_shapes`, `::test_parse_agy_structured_output_any_shape_and_extra_keys`, `::test_parse_agy_strips_ansi` |
| `run_worker` reports an agy `status ERROR` envelope as FAILED even with exit code 0; agy's own print-timeout envelope is FAILED (not TIMEOUT) with zero usage retained; an Eris timeout is TIMEOUT with `usage None` | `test_launch.py::test_run_worker_agy_status_error_is_failed_even_with_exit_code_zero`, `::test_run_worker_agy_print_timeout_envelope_is_failed_with_zero_usage`, `::test_run_worker_agy_eris_timeout_has_no_usage` |
| `parse_grok` prefers `structuredOutput` (camelCase) over parsing `text`; claude schema / no-tools fixtures parse | `test_launch.py::test_parse_grok_schema_fixture_prefers_structured_output`, `::test_parse_claude_schema_and_notools_fixtures` |
| F1: `parse_claude` keeps usage, cost and model names on `is_error`; the message is `result` verbatim when present, else `claude: subtype=… terminal_reason=…: errors` (T2 capture: cap 0.10 tripped at $0.129) | `test_launch.py::test_parse_claude_budget_tripped_fixture_keeps_usage_and_cost`, `::test_parse_claude_error_message_composition` |
| `parse_codex` unwraps the `turn.failed` error OBJECT (E2 401 loop); `parse_grok` surfaces `{type: error, message}` (E17 403) | `test_launch.py::test_parse_codex_401_fixture_is_auth_error_without_usage`, `::test_parse_grok_api_error_fixture_surfaces_message` |
| F2: `invocation_id_for(key, attempt)` = `inv-<key[:16]>-a<n>`, unique per attempt; F3: status OK + `WorkerResult.warning` (never `error`) for "OK with error"; `pgid` recorded from the leader pid (`start_new_session`); `on_spawn` hook fires before waiting; `KeyboardInterrupt` kills the group on the timeout path before re-raising | `test_launch.py::test_invocation_id_is_unique_per_attempt`, `::test_run_worker_ok_with_warning_keeps_status_ok`, `test_run_hermetic.py::test_invoke_full_path_is_hermetic_and_redacted`, `test_run_harness.py::test_sigint_kills_records_and_resume_completes` |
| Idempotency key material includes `executable_sha256` (`idempotency_material`); never the attempt or the arm | `test_launch.py::test_idempotency_key_excludes_arm_includes_repeat` |
| `PARSERS` covers exactly the `CliName` set | `test_launch.py::test_parsers_table_matches_cli_names` |
| `model_executed` is None unless `modelUsage` names exactly one model; all names in `models_used` | `test_launch.py::test_parse_claude_safemode_two_models_means_unknown_model` |
| The pinned path is resolved to its realpath, the realpath is hashed and is what goes in argv[0]; symlink to another file or retargeted symlink is refused | `test_launch.py::test_preflight_hashes_and_executes_the_realpath` |
| Codex `-o` output is read into memory and deleted; no raw output file or schema remains on disk after `run_worker` (also on spawn failure) | `test_launch.py::test_run_worker_codex_output_file_never_stays_on_disk`, `::test_run_worker_codex_scratch_removed_even_on_spawn_failure` |
| The per-call scratch dir is created fresh (`exist_ok=False`; pre-existing entry or symlink refused; symlinked parent refused) and, in the harness, only after `RunWriter` holds the lock | `test_launch.py::test_run_worker_refuses_preexisting_symlink_scratch`, `test_run_hermetic.py::test_invoke_creates_scratch_after_the_lock_and_refuses_planted_symlink` |
| The `-o` file is `lstat`-checked and opened `O_NOFOLLOW`; a non-regular file is refused and never read | `test_launch.py::test_run_worker_refuses_symlinked_output_file` |
| Scratch cleanup failure is never swallowed: `WorkerResult.cleanup_error`, `Invocation.cleanup_error`, a `run.error` event, manifest `extra.cleanup_error`, exit code 4 | `test_launch.py::test_run_worker_codex_cleanup_failure_is_surfaced`, `test_run_hermetic.py::test_invoke_surfaces_cleanup_failure_as_run_error` |
| An over-cap `-o` file is capped and flagged (`output_file_truncated`, `output_file_size`) on the result and the Invocation | `test_launch.py::test_run_worker_codex_output_file_truncation_flag` |
| `snapshot_sha` is only ever read from the snapshot's `.git` (no `--snapshot-sha` flag exists) | `test_run_hermetic.py::test_invoke_key_includes_snapshot_sha_from_git_head` |
| Idempotency key includes the snapshot base commit | `test_launch.py::test_idempotency_key_excludes_arm_includes_repeat`, `test_run_hermetic.py::test_invoke_key_includes_snapshot_sha_from_git_head` |
| Env built from `{}`; NEVER list; only Eris's `GIT_*` hardening allowed | `test_launch.py::test_env_is_built_from_empty_dict`, `::test_never_list_names_are_refused`, `::test_git_hardening_values_are_the_only_git_vars_allowed` |
| `stdin=DEVNULL`, `start_new_session`, `shell=False`, cwd = snapshot realpath | `test_launch.py::test_spawn_passes_hardened_popen_kwargs` |
| stdout AND stderr caps | `test_launch.py::test_spawn_caps_stdout_and_stderr`, `::test_real_caps_and_stdin_devnull` |
| Timeout: SIGTERM to the group, then ALWAYS a SIGKILL sweep of the group (members may ignore TERM or outlive the leader) | `test_launch.py::test_timeout_kills_process_group_sigterm_then_reaps`, `::test_timeout_escalates_to_sigkill`, `::test_timeout_process_already_gone`, `::test_real_process_group_kill_reaches_grandchildren`, `::test_real_group_kill_sweeps_members_that_ignore_sigterm` |
| Pinned executable sha256 checked before spawn | `test_launch.py::test_preflight_executable`, `::test_run_worker_absences_are_statuses_not_exceptions` |
| Envelope parsers match the captured fixtures; claude `is_error` before shape; codex and agy `model_executed=None` | `test_launch.py::test_parse_claude_*`, `::test_parse_codex_*`, `::test_parse_grok_*`, `::test_parse_agy_*` |
| `run_worker` never raises; absence is a status | `test_launch.py::test_run_worker_absences_are_statuses_not_exceptions`, `::test_run_worker_failures` |
| Idempotency key excludes arm, includes repeat_index | `test_launch.py::test_idempotency_key_excludes_arm_includes_repeat` |
| No gemini builder, parser, CLI name or literal remains under `src/eris` (allowed: NEVER-list env names containing GEMINI, `~/.gemini/` paths, the `"gemini-"` model prefix of the lineage guard, `GEMINI.md` and the `".gemini"` directory name of the sanitization minimum) | `test_no_gemini.py::test_no_gemini_literal_in_source`, `::test_no_gemini_builder_parser_or_cli_name`, `::test_the_allowed_gemini_occurrences_are_the_only_ones` |

## Verification allowlist (`src/eris/verify.py`)
| Rule | Test |
|---|---|
| Unknown commands/flags/subcommands, escapes, `.git/`, `@files`, `-`, control chars refused | `test_verify_allowlist.py::test_refused` |
| Hard deny overrides the policy grammar | `test_verify_allowlist.py::test_pytest_hard_deny_even_when_trusted` |
| `requires_trusted` commands refused when untrusted | `test_verify_allowlist.py::test_pytest_allowed_only_when_trusted` |
| Executable pin/hash/presence checked | `test_verify_allowlist.py::test_pin_and_binary_checks` |
| No shell: metacharacters stay one argument | `test_verify_allowlist.py::test_no_shell_so_metacharacters_stay_one_argument` |
| Verify env from `{}` with git hardening | `test_verify_allowlist.py::test_verify_env_is_built_from_empty_and_git_hardened` |
| `run_allowlisted` takes RAW argv and re-applies `check_command` immediately before spawn; a forged or stale `Decision` cannot reach `spawn` | `test_verify_allowlist.py::test_run_allowlisted_revalidates_raw_argv_before_spawn`, `::test_forged_decision_cannot_reach_spawn`, `::test_run_allowlisted_refuses_forbidden_launch_tokens` |
| Every `HARD_DENY` entry is a real flag of the pinned tool version (captured `--help` in `tests/fixtures/help/`: git 2.50.1 global + `-h`/man of log, grep, show, diff, status, ls-files, blame, rev-parse; pytest 9.1.1; ruff 0.16.4; mypy 2.3.1; captured 2026-08-22). Every policy-allowlisted flag appears in that help; for git, in the help of at least one declared subcommand | `test_verify_allowlist.py::test_every_hard_deny_entry_is_a_real_flag_of_the_pinned_tool`, `::test_mandatory_hard_deny_entries_present`, `::test_default_policy_allowlists_only_real_flags`, `::test_git_subcommand_help_fixtures_are_full_captures` |

## Snapshots (`src/eris/snapshot.py`)
| Rule | Test |
|---|---|
| No future OBJECT (commit, tree, blob: `rev-list --objects --all --not <pre_fix>` in the source mirror) present; no remote; no alternates; only the snapshot ref | `test_snapshot.py::test_snapshot_has_no_future` (real git: commit, tree and blob asserted) |
| The verifier detects each problem class, including an injected future blob/tree id | `test_snapshot.py::test_verify_detects_each_problem`, `::test_verify_rejects_injected_future_blob_and_tree` |
| `read_head_sha` is filesystem-only (detached HEAD, loose ref, packed-refs; refuses `..` refs) | `test_snapshot.py::test_read_head_sha_filesystem_only` |
| Build sequence and cleanup (mirror removed, hooks/FETCH_HEAD removed) | `test_snapshot.py::test_build_snapshot_sequence_with_fake_git`, `::test_build_snapshot_unknown_sha_fails_and_cleans_mirror` |

## Doctor and harness
| Rule | Test |
|---|---|
| Doctor never prints secret values | `test_doctor.py::test_doctor_never_prints_secret_values`, `::test_cli_doctor` |
| Missing worker is WARN; changed binary is FAIL | `test_doctor.py::test_missing_worker_is_warn_not_fail`, `::test_changed_binary_is_fail` |
| `--probe` never executes an unpinned or hash-mismatched binary; probe output is passed through the redactor before printing | `test_doctor.py::test_probe_output_is_redacted_and_mismatched_binary_is_never_probed` |
| After a credential-file parse failure NO worker is probed (the redactor would lack those values) | `test_doctor.py::test_probe_skipped_entirely_on_credential_parse_failure` |
| The doctor reports the size of agy's `~/.gemini/antigravity-cli/{brain,conversations}` (byte counts only, never file names or content; WARN ≥ 256 MiB); Eris never deletes vendor state | `test_doctor.py::test_agy_state_dir_size_is_reported_and_warns_when_large` |
| A declared credential file that is missing is WARN; one that exists but cannot be parsed is FAIL (doctor) / refuses the run (harness) | `test_doctor.py::test_unparsable_credential_file_is_fail_missing_is_warn`, `test_redact.py::test_load_credential_values_from_json_files`, `test_run_hermetic.py::test_invoke_refuses_unparsable_credential_file` |
| Run ids match `^[A-Za-z0-9_-]{1,64}$` and are validated BEFORE any path is built; the run dir must sit directly under the runs dir | `test_run_hermetic.py::test_invoke_refuses_unsafe_run_ids_before_touching_disk`, `::test_run_id_helpers` |
| flock probe | `test_doctor.py::test_doctor_never_prints_secret_values`, `::test_flock_probe_failure_is_fail` |
| `dry-run` spawns nothing | `test_run_hermetic.py::test_dry_run_prints_plan_and_spawns_nothing` |
| `invoke` records absence and failure instead of substituting | `test_run_hermetic.py::test_invoke_records_absence_for_unpinned_worker`, `::test_invoke_failed_worker_is_recorded` |

## Retry (`src/eris/retry.py`) - unknown is terminal
| Rule | Test |
|---|---|
| The pattern table is DATA and matches the captured fixtures: T2 → `budget_tripped`; T3/E2/A8 → `auth_terminal`; A5/A16/E17 → `policy_terminal`; A7 → `timeout`; grok `cancelled` → `ok_with_warning`; a pattern scoped to one CLI never fires for another | `test_retry.py::test_pattern_table_against_captured_fixtures`, `::test_pattern_table_is_data_and_every_entry_names_a_class` |
| Status rules: TIMEOUT retryable (weight 2) except for the judge (ADJUDICATE/SUMMARIZE: terminal, E8); REFUSED/MISSING → `policy_terminal`; `spawn failed`/`cannot write schema` → `transient_io`; codex no-JSONL is transient ONLY with rc ≠ 0 and empty stdout; schema requested + `structured` None → `malformed_output`; anything else UNKNOWN = terminal | `test_retry.py::test_classify_status_rules`, `::test_classify_codex_empty_stdout_is_transient_only_with_nonzero_exit`, `::test_classify_ok_with_schema_but_no_structured_is_malformed_output` |
| Backoff: timeout 30 s × attempt, transient 10·2^(n−1), malformed 0; retry weight budget 3 per call (timeout 2, others 1); `malformed_output` retries capped at 2 | `test_retry.py::test_backoff_schedule`, `::test_retry_weight_budget_and_malformed_cap` |
| `BudgetLedger`: known and reserved spend never blended; pre-check `spent_known + reserved + per_call > ceiling` (run and campaign); a ceiling EXACTLY equal to the committed spend trips; a missing cost reserves `per_call_usd` (×2 for a timeout) | `test_retry.py::test_budget_ledger_precheck_and_reservations`, `::test_budget_ledger_campaign_ceiling` |
| Driver: every attempt = `Invocation` (`inv-…-a<n>`, pgid, prompt_sha256, warning) + `CostRecord` (`counted=True`; cost None → estimated per_call, `cost_known=False`) + `RetryAttempt`; `retry.scheduled` before the injected sleep; identical prompt in a fresh process; STOP between attempts lets the in-flight attempt finish; money pre-check before EVERY spawn (F4: `BUDGET_TRIPPED` invocation + `budget.tripped`, nothing spawned); the claude cap-trip envelope is recorded as `BUDGET_TRIPPED` with its real cost; terminal classes and the judge timeout are never retried; writer errors propagate unclassified; `output_check` turns an OK result into `malformed_output` | `test_retry.py::test_driver_retries_a_timeout_once_then_succeeds`, `::test_driver_stop_between_attempts_lets_the_attempt_finish_and_does_not_retry`, `::test_driver_budget_precheck_trips_before_the_first_spawn`, `::test_driver_budget_precheck_trips_between_attempts`, `::test_driver_claude_budget_envelope_becomes_budget_tripped_status`, `::test_driver_malformed_output_retries_identical_prompt_up_to_cap`, `::test_driver_terminal_failure_is_not_retried`, `::test_driver_judge_timeout_is_terminal`, `::test_driver_writer_errors_propagate_and_are_never_classified`, `test_stages.py::test_malformed_output_retries_identical_prompt_then_absent` |
| STOP files: `runs/STOP` and `runs/<campaign>/STOP` | `test_retry.py::test_stop_requested_checks_every_path` |

## Cache (`src/eris/cache.py`) - write-once, redacted bytes only, never under `runs/`
| Rule | Test |
|---|---|
| Entry file = sha256 of its redacted bytes (from `put_blob`), `keys/<key>` pointer, blob copies; a hit replays blobs through `put_blob`, re-appends the cached `Invocation` with `reused_from`, `CostRecord(counted=False)`, `invocation.reused`; no secret under `cache/` | `test_cache.py::test_store_then_hit_replays_blobs_and_records_reuse` |
| HIT requires: current pin (`executable_sha256`; unpinned/disabled never hits), key + prompt match, same campaign unless `reuse_across_campaigns`, status ok, `scan_hits == 0`, model known, current `schema_version`, entry hash == name, every blob re-hashes; `fresh` skips the lookup and stores only when absent | `test_cache.py::test_hit_requirements_each_refuse`, `::test_reuse_across_campaigns_flag_and_fresh`, `::test_contaminated_failed_or_modelless_entries_never_hit` |
| Tampered entry (hash ≠ name), symlinked key/entry/blob, garbage pointer, tampered blob → reasoned miss, never followed | `test_cache.py::test_tampered_entry_symlinked_files_and_bad_blobs_are_refused` |
| Write-once: a different entry under an existing key is a `conflict`, nothing overwritten; a replay whose blob changes under re-redaction is refused; `cache_dir` under `runs/` refused; no `O_NOFOLLOW` (Windows) → `CacheUnsupported` (documented refusal) | `test_cache.py::test_write_once_conflict_never_overwrites`, `::test_replay_refuses_a_blob_that_changes_under_redaction`, `::test_cache_refuses_runs_dir_and_platforms_without_o_nofollow`, `::test_store_refuses_mismatched_key_and_symlinked_dirs` |
| In the stages: a hit skips the spawn and records the reuse; a contaminated entry (`scan_hits > 0`) is stored but never replayed | `test_stages.py::test_cache_hit_replays_and_skips_the_spawn`, `::test_contaminated_call_is_stored_with_scan_hits_and_never_replayed` |

## Sanitization (`src/eris/sanitize.py`) - agy/grok proposer+critic only; verification on the original
| Rule | Test |
|---|---|
| Strip list = policy additions over the enforced minimum (AGENTS.md, CLAUDE.md, CLAUDE.local.md, GEMINI.md, GROK.md; .agents, .claude, .codex, .gemini, .grok, .antigravity, .cursor, .github/copilot-instructions.md), matched by name at any depth, case-insensitively, slash entries as path suffixes; the policy can add, never remove | `test_sanitize.py::test_profile_minimum_any_depth_case_insensitive_and_slash_entries`, `::test_profile_from_policy_adds_but_never_removes` |
| The original is never written (tree hash + inodes unchanged); the copy == original − stripped − `.git/hooks` − dropped symlinks (tree-hash equality); new inodes (no hardlinks); symlinks kept only when relative, inside the tree and not into a stripped entry; `.git` copied without hooks; `AGENTS.md` as a symlink and `.agents` as a FILE are stripped; no `.git` is fine; a stripped directory records every file | `test_sanitize.py::test_sanitize_strips_minimum_and_leaves_the_original_untouched`, `::test_edge_cases_agents_md_symlink_dot_agents_file_and_no_git`, `::test_stripped_directory_records_every_file_and_nested_symlinks`, `::test_tree_sha256_is_order_independent_and_sees_symlink_targets` |
| Refusals: missing original, pre-existing dest (`make_private_dir`), copy inside the original, fifo/special files | `test_sanitize.py::test_refusals` |
| agy's `--add-dir` equals the copy root; the copy lives under the run scratch and is removed in `finally`; a cleanup failure raises `SanitizeCleanupError` (never swallowed); verification commands run on the ORIGINAL | `test_sanitize.py::test_agy_add_dir_is_the_copy_root`, `::test_sanitized_copy_cleanup_failure_is_raised_never_swallowed`, `test_evidence.py::test_pack_commands_run_on_the_original_not_the_sanitized_copy`, `::test_evidence_requests_run_on_the_original_snapshot`, `test_run_harness.py::test_run_one_cell_end_to_end` |

## Contamination scan (`src/eris/scan.py`) - detect only, hashes and counts only
| Rule | Test |
|---|---|
| Patterns are derived at run time (source-repo path, fixed markers, vendor memory paths under `~`, key.json fix hunks / extra strings, policy strings; never `must_mention`), whitespace-folded, sha256-named | `test_scan.py::test_patterns_are_derived_at_runtime_and_folded` |
| Dropped and COUNTED, never listed: < 12 chars (fixed markers exempt), present in the pre-fix tree, duplicates, contained in the harness's own recorded paths (`known_texts`) | `test_scan.py::test_nondistinctive_patterns_are_dropped_and_counted`, `::test_harness_own_paths_cannot_be_patterns` |
| Every blob, every event payload (malformed lines raw), the pack and reused cache entries are scanned; `scan.result` carries `ScanResult` only (no pattern text anywhere in the ledger line); re-scanning over the scan event adds no hits; truncated stdout or an empty-stdout TIMEOUT → `scan_incomplete` | `test_scan.py::test_scan_text_folds_whitespace_and_counts`, `::test_scan_covers_blobs_events_pack_and_cache_and_records_hashes_only`, `::test_rescanning_over_the_scan_event_itself_adds_no_hits`, `::test_scan_incomplete_on_truncated_stdout_or_empty_timeout`, `::test_scan_run_tolerates_missing_dirs_malformed_lines_and_symlinked_blobs` |

## Evidence pack and requests (`src/eris/evidence.py`)
| Rule | Test |
|---|---|
| `task.json` is strict (no answer key inside); `derive_nonce` is deterministic (32 hex) over snapshot/task/repeat/stage/policy | `test_evidence.py::test_task_spec_is_strict`, `::test_nonce_is_deterministic_and_32_hex` |
| The pack is content-derived (`ev-<sha[:16]>`, identical across runs), carries no timestamp or run id, is a blob of the run (`pack_sha256`), records one `evidence.item` per item + `pack.built`; origins are never blurred; the executable basename (not the host path) is id material | `test_evidence.py::test_pack_is_content_derived_identical_across_runs_and_carries_no_clock`, `::test_pack_is_redacted_before_hashing` |
| Pack commands and evidence requests run on the ORIGINAL snapshot with the hardened verify env | `test_evidence.py::test_pack_commands_run_on_the_original_not_the_sanitized_copy`, `::test_evidence_requests_run_on_the_original_snapshot` |
| Refusals are EVENTS (`verify.refused` / `evidence.refused`), the pack still builds (`pack.incomplete`); excerpts confined (relative, inside, never `.git`, never through a symlink, regular files, 200-line cap); large outputs head+tail capped in the pack, whole in the blob; STOP before each command | `test_evidence.py::test_pack_refusals_are_events_and_the_pack_still_builds`, `::test_excerpts_are_confined_and_capped`, `::test_large_command_output_is_head_tail_capped_in_the_pack_but_whole_in_the_blob`, `::test_stop_during_pack_build_runs_no_further_command` |
| Requests: dedupe by canonical argv (`verify.duplicate`), `max_requests_per_run` and `max_wall_s` refuse with a reason, STOP before every command, `expect_exit_code` recorded beside the observed code | `test_evidence.py::test_evidence_requests_refusals_dedupe_caps_and_expectations`, `::test_evidence_requests_stop_before_a_command` |
| `verify_scratch`: private dir under the run (planted symlink refused), removed in `finally`; cleanup failure = `run.error` + `EvidenceCleanupError` | `test_evidence.py::test_verify_scratch_is_private_removed_and_cleanup_failure_is_a_run_error` |

## Stages (`src/eris/stages.py`, `eval/prompts/*.md`)
| Rule | Test |
|---|---|
| Prompt files are frozen (ROLE + RULES, no DATA/OUTPUT SCHEMA of their own), hashed per run | `test_stages.py::test_prompt_files_are_frozen_with_role_and_rules_sections`, `::test_prompt_files_missing_sections_are_refused` |
| The wire schema is inlined, closed (`additionalProperties: false`) and every key required at every level | `test_stages.py::test_wire_schema_is_inlined_closed_and_all_required` |
| DATA is ONE canonical JSON document between nonce delimiters; repo text only inside strings; a nonce inside the data becomes `[NONCE]` + `envelope.nonce_collision`; a prompt > 256 KiB is refused, never spilled | `test_stages.py::test_render_prompt_sections_nonce_delimiters_and_cap` |
| Model output is parsed only through the wire models: a model-supplied id, `origin`, `schema_version` or engine field is `malformed_output`; adversarial text (`"]}}`, the nonce, "ignore previous instructions") stays inside a JSON string | `test_stages.py::test_parse_wire_rejects_engine_fields_ids_and_non_objects`, `::test_adversarial_proposal_text_stays_data` |
| Eris assigns every id from the propose key (`clm-`, `fnd-`, `prop-`, `<key>-p<k>-c<n>`, `dis-`); out-of-range claim indexes and invalid refs are rejected | `test_stages.py::test_ids_are_assigned_by_eris_and_derived_from_the_propose_key` |
| `stage.started`/`invocation.finished`/`cost`/`retry.attempt`/`proposal.recorded`/`stage.finished`; the prompt contains no host absolute path; malformed output retries the identical prompt twice then `worker.absent`; judge TIMEOUT terminal | `test_stages.py::test_propose_records_proposal_and_stage_events`, `::test_malformed_output_retries_identical_prompt_then_absent`, `::test_judge_timeout_is_terminal_and_absent` |
| Critics never see each other (one prompt hash, no challenge text, lens `framing`); challenge ids unique per critic | `test_stages.py::test_critics_never_see_each_other_and_carry_framing` |
| Judge input contract: evidence blocks (16 KiB head+tail), P1..Pn (`proposal.labels`), C1.., verification items; executable basenames only; no other stage's instruction text; `tools: []`; after the judge `adjudication.raw` → `.enforced` → `validate.findings`; the arm-3 judge prompt has no critiques and hashes differently from arm 4's; the summarizer uses its own prompt file and records raw + enforced | `test_stages.py::test_judge_input_contract_and_enforcement_events`, `::test_arm3_judge_prompt_has_no_critiques_and_differs_from_arm4`, `::test_summarizer_uses_its_own_prompt_file_and_records_raw_and_enforced`, `::test_build_call_uses_role_tools_and_sanitized_cwd` |

## Arms (`src/eris/arms.py`) and ledger (`src/eris/ledger.py`)
| Rule | Test |
|---|---|
| The arm table is data in the fixed order; `CellSpec` validates judge/critics/single | `test_arms.py::test_arm_table_is_data_in_the_fixed_order` |
| PAIRED ABLATION: one world, arms 3/3b/4 → ONE set of propose spawns; 3b/4 carry `invocation.reused`; propose blob hashes equal across run dirs (and present in each); adjudicator prompt hashes differ; arm 3's judge prompt has no critique text; no `Invocation` carries an arm; `single` reuses the panel proposal | `test_arms.py::test_paired_ablation_one_set_of_propose_spawns_across_arms_3_3b_4`, `::test_single_arm_reuses_the_panel_proposal_via_cache` |
| STOP before every step and before every worker call: the next FIRST attempt never spawns; remaining stages `stage.skipped`; missing cells recorded; budget trip → `cell.missing` + `stage.skipped{budget}` for the rest | `test_arms.py::test_stop_at_a_cell_boundary_prevents_the_next_first_attempt`, `::test_stop_at_a_step_boundary`, `::test_budget_trip_marks_the_cell_missing_and_skips_the_remaining_stages` |
| `adjudicate_iter`: the judge's requests are executed and the judge re-run (cap 3; nothing new → stop; no new proposals/critiques); consensus records raw + enforced from the summarizer; an absent judge is a missing cell; no proposals → critique/judge skipped | `test_arms.py::test_adjudicate_iter_executes_the_judges_requests_and_reruns`, `::test_adjudicate_iter_caps_at_max_iterations`, `::test_consensus_records_raw_and_enforced_and_summarizer_role`, `::test_judge_absent_is_a_missing_cell`, `::test_no_proposals_skips_critique_and_judge` |
| Resume: finished stages whose blobs re-hash are replayed (`stage.resumed`); an open attempt gets `invocation.abandoned` + a pessimistic cost; stale pgids (from `invocation.spawned`) are killed SIGTERM→SIGKILL; stale `scratch/call-*` removed; a tampered blob re-runs that worker; no `os.killpg` → documented refusal | `test_arms.py::test_resume_replays_finished_stages_and_abandons_the_open_attempt`, `::test_resume_does_not_trust_a_tampered_blob`, `::test_kill_stale_groups_refuses_without_killpg_and_skips_dead_groups` |
| Cost totals distinguish spent (counted) from attributed (reused included), known from reserved, by stage | `test_arms.py::test_cost_totals_distinguish_spent_attributed_and_unknown` |

## Harness (`eval/run.py`: `run`, `campaign`, `campaign status`)
| Rule | Test |
|---|---|
| `run` finalizes a cell: `run.started` (prompt file hashes, containment, snapshot sha), sanitized copies (removed), verification on the original, `scan.patterns`, `scan.result`, cache stores, `arm.finished`, manifest extras; stderr = one JSON line per stage event; judge argv carries `--tools ""` | `test_run_harness.py::test_run_one_cell_end_to_end` |
| Exit codes: 3 incomplete, 6 contaminated (the fix hunk from `key.json` never appears in the scan line), 5 STOP (nothing spawns), 2 finalized-dir resume / bad run id / unknown worker, 4 corrupt ledger | `test_run_harness.py::test_run_exit_codes_incomplete_contaminated_stop_and_refusals` |
| SIGINT (handler only in `eval/run.py`, restored afterwards): the group is killed on the existing path, `invocation.finished` (failed, `interrupted`, cost not known), `run.interrupted`, exit 130, no manifest; `--resume` replays the proposals and re-runs only the judge | `test_run_harness.py::test_sigint_kills_records_and_resume_completes` |
| Campaign: `--dry-run` prints the task-major → repeat → fixed-arm order and writes nothing; cells share proposals; `campaign status` is read-only; a finalized campaign refuses without `--resume`; STOP in the campaign dir skips the next cell (exit 5); `--resume` skips finalized cells and resumes unfinished ones | `test_run_harness.py::test_campaign_dry_run_run_status_and_resume`, `::test_campaign_resume_skips_finalized_cells_and_resumes_unfinished` |

## Scorer (`eval/score.py`) - read-only
| Rule | Test |
|---|---|
| `key.json` v1 is strict; the scorer imports nothing that executes (AST) and opens nothing outside the runs dir + corpus | `test_score.py::test_key_format_is_strict`, `::test_score_imports_nothing_that_executes`, `::test_scorer_opens_nothing_outside_runs_and_corpus` |
| E1 gate: `revert`/`planted`/`insufficient` require `ArmRun.containment == "container"` (exit 7, no metrics, no CLI override); `control`/`plan` score normally | `test_score.py::test_e1_gate_refuses_defect_categories_without_containment` |
| Contaminated (recorded or re-scan) / `scan_incomplete` → excluded but costed; BUDGET_TRIPPED → `missing`; incomplete judge → `incomplete`; invalid ledger → listed, not scored | `test_score.py::test_contaminated_missing_and_incomplete_cells_are_excluded_but_costed`, `::test_ledger_invalid_cells_are_listed_not_scored` |
| Matching: path + line overlap within tolerance + `must_mention`; 0/0 → None; distractor hits are FPs; high/critical FPs are confident-wrong | `test_score.py::test_matching_precision_recall_tolerance_must_mention_and_distractors` |
| Arm 1 findings from the proposal (no verdict); arm 2 on the RAW summarizer verdict; other arms on the enforced verdict; spent vs attributed cost by stage; paired deltas 3b−3 and 4−3 only with identical `propose_keys` and both cells included | `test_score.py::test_cells_are_scored_with_verdict_basis_costs_and_paired_deltas`, `::test_paired_deltas_require_identical_propose_keys_and_inclusion`, `::test_read_cell_and_load_key_errors` |

## Gate
`task ci` = ruff check + ruff format --check + mypy strict (src) + mypy (eval)
+ pytest with coverage >= 90 on `src` + `eval` + pip-audit (blocking). The
coverage floor only ratchets up (80 -> 90 in 0.3.0).
