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

Exception (stated in AGENTS.md as well): the marker accepts `allow=["git"]`
and its single call site is `test_snapshot.py::test_snapshot_has_no_future`
(plus `test_hermeticity.py::test_marker_allow_extends_the_list`, which proves
the allow list is honoured). No other test may spawn `git`.

## Schemas (`src/eris/schemas.py`)
| Rule | Test |
|---|---|
| Canonical bytes of every record type are pinned per `SCHEMA_VERSION` | `test_schemas.py::test_golden_bytes_pinned`, `::test_every_record_type_has_a_golden_file` |
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
| `trusted` defaults to False | `test_policy.py::test_repo_default_policy_loads_and_is_untrusted_and_unpinned` |
| Secret-shaped value in policy or pins refuses the load | `test_policy.py::test_secret_shaped_value_refuses_load`, `::test_secret_in_pins_file_refuses` |
| API hosts allowlisted; https only except loopback | `test_policy.py::test_api_worker_host_and_scheme_rules` |
| Provider must be in `vendors_allowed` | `test_policy.py::test_provider_not_in_vendors_refuses` |
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
| No secret anywhere on disk (plain, ANSI-split, base64, payload, manifest extra) | `test_writer.py::test_no_secret_anywhere_on_disk`, `test_run_hermetic.py::test_invoke_full_path_is_hermetic_and_redacted` |

## Launcher (`src/eris/launch.py`)
| Rule | Test |
|---|---|
| argv per CLI exactly as specified | `test_launch.py::test_claude_argv_exactly_as_specified`, `::test_codex_argv_exactly_as_specified`, `::test_gemini_and_grok_argv_exactly_as_specified` |
| Forbidden tokens refused in every argv element EXCEPT the prompt (which may quote them); prompts starting with `-` refused | `test_launch.py::test_forbidden_tokens_are_refused_outside_the_prompt`, `::test_argv_hygiene` |
| `model_executed` is None unless `modelUsage` names exactly one model; all names in `models_used` | `test_launch.py::test_parse_claude_safemode_two_models_means_unknown_model` |
| The pinned path is resolved to its realpath, the realpath is hashed and is what goes in argv[0]; symlink to another file or retargeted symlink is refused | `test_launch.py::test_preflight_hashes_and_executes_the_realpath` |
| Codex `-o` output is read into memory and deleted; no raw output file or schema remains on disk after `run_worker` (also on spawn failure) | `test_launch.py::test_run_worker_codex_output_file_never_stays_on_disk`, `::test_run_worker_codex_scratch_removed_even_on_spawn_failure` |
| Idempotency key includes the snapshot base commit | `test_launch.py::test_idempotency_key_excludes_arm_includes_repeat`, `test_run_hermetic.py::test_invoke_key_includes_snapshot_sha_from_git_head` |
| Env built from `{}`; NEVER list; only Eris's `GIT_*` hardening allowed | `test_launch.py::test_env_is_built_from_empty_dict`, `::test_never_list_names_are_refused`, `::test_git_hardening_values_are_the_only_git_vars_allowed` |
| `stdin=DEVNULL`, `start_new_session`, `shell=False`, cwd = snapshot realpath | `test_launch.py::test_spawn_passes_hardened_popen_kwargs` |
| stdout AND stderr caps | `test_launch.py::test_spawn_caps_stdout_and_stderr`, `::test_real_caps_and_stdin_devnull` |
| Timeout: SIGTERM to the group, then ALWAYS a SIGKILL sweep of the group (members may ignore TERM or outlive the leader) | `test_launch.py::test_timeout_kills_process_group_sigterm_then_reaps`, `::test_timeout_escalates_to_sigkill`, `::test_timeout_process_already_gone`, `::test_real_process_group_kill_reaches_grandchildren`, `::test_real_group_kill_sweeps_members_that_ignore_sigterm` |
| Pinned executable sha256 checked before spawn | `test_launch.py::test_preflight_executable`, `::test_run_worker_absences_are_statuses_not_exceptions` |
| Envelope parsers match the captured fixtures; claude `is_error` before shape; codex `model_executed=None` | `test_launch.py::test_parse_claude_*`, `::test_parse_codex_*`, `::test_parse_grok_*`, `::test_parse_gemini_defensive_modes` |
| `run_worker` never raises; absence is a status | `test_launch.py::test_run_worker_absences_are_statuses_not_exceptions`, `::test_run_worker_failures` |
| Idempotency key excludes arm, includes repeat_index | `test_launch.py::test_idempotency_key_excludes_arm_includes_repeat` |

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
| Every `HARD_DENY` entry is a real flag of the pinned tool version (captured `--help` in `tests/fixtures/help/`: git 2.50.1, pytest 9.1.1, ruff 0.16.4, mypy 2.3.1, captured 2026-08-22); every policy-allowlisted flag exists too | `test_verify_allowlist.py::test_every_hard_deny_entry_is_a_real_flag_of_the_pinned_tool`, `::test_mandatory_hard_deny_entries_present`, `::test_default_policy_allowlists_only_real_flags` |

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
| A declared credential file that is missing is WARN; one that exists but cannot be parsed is FAIL (doctor) / refuses the run (harness) | `test_doctor.py::test_unparsable_credential_file_is_fail_missing_is_warn`, `test_redact.py::test_load_credential_values_from_json_files`, `test_run_hermetic.py::test_invoke_refuses_unparsable_credential_file` |
| Run ids match `^[A-Za-z0-9_-]{1,64}$` and are validated BEFORE any path is built; the run dir must sit directly under the runs dir | `test_run_hermetic.py::test_invoke_refuses_unsafe_run_ids_before_touching_disk`, `::test_run_id_helpers` |
| flock probe | `test_doctor.py::test_doctor_never_prints_secret_values`, `::test_flock_probe_failure_is_fail` |
| `dry-run` spawns nothing | `test_run_hermetic.py::test_dry_run_prints_plan_and_spawns_nothing` |
| `invoke` records absence and failure instead of substituting | `test_run_hermetic.py::test_invoke_records_absence_for_unpinned_worker`, `::test_invoke_failed_worker_is_recorded` |

## Gate
`task ci` = ruff check + ruff format --check + mypy strict (src) + mypy (eval)
+ pytest with coverage >= 80 on `src` + `eval` + pip-audit (blocking). The
coverage floor only ratchets up.
