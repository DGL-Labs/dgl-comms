# Pingzo C-1a: repository settings, rulesets and environment (exact calls)

Authority: DIRECT-DGL-COMMS-APP-1-C1-BUILD-GO-1 (Governance a769621), step C-1a only. Plan: C1-PLAN-r4 (619431986112) §6 and §9, with ADDENDUM-1 (0833c15d).
Order: the G5 review covers this file and the pull request. Nothing here is applied before G5 PASS; Taylor's line 576cfbf8 names C&D as the applier. Every write is preceded by a B0 GET whose output is recorded, so each change can be undone exactly.
Repo: `R=repos/DGL-Labs/dgl-comms`. All calls are `gh api` with `-H "X-GitHub-Api-Version: 2022-11-28"` (omitted below for length).
Pinned values come from read-only lookups on 2026-10-16; sources are in the PR body.

## B0. Record the state before (read-only)
```sh
gh api $R --jq '{visibility, default_branch, owner: .owner.login}'
gh api $R/actions/permissions                            # enabled, allowed_actions
gh api $R/actions/permissions/workflow                   # default_workflow_permissions, can_approve_pull_request_reviews
gh api $R/actions/permissions/selected-actions           # 409 if allowed_actions is not "selected"; recorded as is
gh api $R/actions/permissions/fork-pr-contributor-approval
gh api $R/rulesets
gh api $R/environments/claude
gh api $R/environments/claude/deployment-branch-policies
gh api $R/environments/claude/secrets --jq '[.secrets[].name]'   # names only; values are never readable
```

## B1. Repository Actions settings (plan §6)
```sh
# Default GITHUB_TOKEN read-only; Actions may not create or approve pull requests.
gh api -X PUT $R/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false

# Approval required for every outside contributor's fork workflow run.
gh api -X PUT $R/actions/permissions/fork-pr-contributor-approval \
  -f approval_policy=all_external_contributors

# Only the SHA-pinned actions used by this repository may run.
gh api -X PUT $R/actions/permissions -F enabled=true -f allowed_actions=selected
gh api -X PUT $R/actions/permissions/selected-actions --input - <<'JSON'
{
  "github_owned_allowed": false,
  "verified_allowed": false,
  "patterns_allowed": [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "anchore/sbom-action@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c",
    "anthropics/claude-code-action@97c53473391bff1901034d4b454b5bac7ab7a029",
    "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"
  ]
}
JSON
```
- **Nested actions (verified, G5 SHOULD 5).** At 97c53473, claude-code-action's `action.yml` has exactly one `uses:`, which is `oven-sh/setup-bun@0c5077e5…` (v2.2.0). setup-bun at that sha is `using: node24` and nests nothing. checkout (node24) and sbom-action (node24) nest nothing either. Read 2026-10-16 from each `action.yml` at the pinned sha.
- **Check after apply.** After merge, the first approved claude run (T-C1A-4) must start under this allowlist. If GitHub refuses an action, the run log names it, and the list is corrected through a PR.
- **`workflows` permission.** `GITHUB_TOKEN` has no `workflows` scope, and no workflow declares `write-all`. GitHub refuses any `GITHUB_TOKEN` push that changes `.github/workflows/`, so the builder cannot edit workflows.

## B2. Rulesets (plan §9)
**B2a: the default branch.**
```sh
gh api -X POST $R/rulesets --input - <<'JSON'
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": false } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "secrets (gitleaks, full history)", "integration_id": 15368 },
          { "context": "licenses (allowlist and SBOM)", "integration_id": 15368 },
          { "context": "gitignore (.env* is ignored)", "integration_id": 15368 } ] } }
  ]
}
JSON
```
- **Bypass.** Actor 5 with type `RepositoryRole` is the Repository admin role. Its `bypass_mode` is `pull_request`, so the admin cannot push directly either; the admin merges through a pull request. There is no bypass for `github-actions` or any app. `integration_id` 15368 is GitHub Actions.

**B2b: tags (G5 SHOULD 7).** Only the admin may create, move or delete tags. The builder's `contents: write` cannot.
```sh
gh api -X POST $R/rulesets --input - <<'JSON'
{
  "name": "tags-admin-only",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" }, { "type": "non_fast_forward" } ]
}
JSON
```

**Branches other than `main` (accepted exposure).** During an approved run, the builder's token can push to or delete any branch except `main`, including `claude/**` and other PR branches.
- This is bounded:
  - each run needs Taylor's approval;
  - `main` and tags are protected;
  - anything reaching `main` passes review and the checks.
- Revisit at C-1l: a ruleset for `claude/**` that limits deletion.

## B3. Environment `claude` (MUST 1 of G5 round 1)
Taylor created it, with required reviewer BoaterGuy15 (id 86842551) and secret `ANTHROPIC_API_KEY`. **The secret is never read or written.** The only change is **required**: limit deployments to `main`.
- **Values come from B0.** The PUT body is built from the B0 GET, never typed in.
- **Stop rule.** Before the PUT, B0 is compared with the reviewed state, which was read 2026-10-16:
  - one required reviewer, User 86842551;
  - `prevent_self_review` false;
  - no wait timer;
  - `can_admins_bypass` true;
  - no branch policy.

  **On any difference, stop** and report it. Nothing is applied.
```sh
gh api $R/environments/claude > b0-env.json
# Compare with the reviewed state and build the PUT body from B0 (Python, already on the applier's PC; no jq).
python -I - b0-env.json > b3-put.json <<'PY' || { echo "B0 differs from the reviewed state; stopping before any write" >&2; exit 1; }
import json, sys
e = json.load(open(sys.argv[1]))
rr = [p for p in e.get("protection_rules", []) if p["type"] == "required_reviewers"]
wt = [p for p in e.get("protection_rules", []) if p["type"] == "wait_timer"]
reviewers = [{"type": r["type"], "id": r["reviewer"]["id"]} for p in rr for r in p["reviewers"]]
ok = (len(rr) == 1 and reviewers == [{"type": "User", "id": 86842551}] and rr[0]["prevent_self_review"] is False
      and not wt and e.get("can_admins_bypass") is True and e.get("deployment_branch_policy") is None)
if not ok:
    sys.exit("differs: " + json.dumps({"reviewers": reviewers, "rules": e.get("protection_rules"),
             "can_admins_bypass": e.get("can_admins_bypass"), "deployment_branch_policy": e.get("deployment_branch_policy")}))
print(json.dumps({"wait_timer": 0, "prevent_self_review": rr[0]["prevent_self_review"], "reviewers": reviewers,
                  "can_admins_bypass": e["can_admins_bypass"],
                  "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}))
PY
gh api -X PUT $R/environments/claude --input b3-put.json
gh api -X POST $R/environments/claude/deployment-branch-policies -f name=main -f type=branch

# Verify
gh api $R/environments/claude --jq '{reviewers: [.protection_rules[] | select(.type=="required_reviewers") | .reviewers[].reviewer.login], deployment_branch_policy}'
gh api $R/environments/claude/deployment-branch-policies --jq '[.branch_policies[] | {name, type}]'   # expect [{"name":"main","type":"branch"}]
gh api $R/environments/claude/secrets --jq '[.secrets[].name]'                                          # expect ["ANTHROPIC_API_KEY"]
```
- **Why this is safe.** claude.yml triggers on `issue_comment` only. GitHub runs that event from the workflow file on the **default branch**, with `GITHUB_REF` set to `main`, so the `main` limit admits it.
- **What it blocks.** A workflow on any other branch or PR ref, such as a copy of claude.yml edited in a PR, cannot use the environment, so it cannot reach the key.
- **Why `pull_request_review_comment` was removed.** That event runs the workflow from the PR merge ref, so a PR could change its own allowlist and tools.

## Building with the Claude action (operating notes; G5 SHOULD 3)
- **Pushes don't trigger CI.** Pushes made with `GITHUB_TOKEN` (the builder's commits) start no `push` or `pull_request` workflows, so the three required checks will not run on them. **Workaround:** Taylor closes and reopens the PR, or pushes an empty commit to its branch. Either way, ci.yml runs on the head that will be merged.
- **Approvals.** With `require_last_push_approval`, the latest push must be approved by someone other than its pusher. Taylor authors the PRs, and Taylor cannot approve his own PR, so approvals are not obtainable while he is the only human reviewer. Merges go through the admin bypass (pull-requests-only mode) after G5 PASS, as plan §9 says. The rule stays, so a second reviewer account works without changes.

## Residual risk (G5 MUST 2)
- **The key is in the action's process environment.** Claude has no Bash. `--disallowedTools` denies reads of:
  - `/proc` and `/sys`;
  - the runner `_temp` folder;
  - the action cache (`/home/runner/work/_actions`);
  - the runner install (`/home/runner/runners`);
  - dot-directories under `/home/runner`.

  Commits go through the GitHub API (`use_commit_signing`), so no `git` runs in Bash.
- **What is not proven:**
  - The deny rules are enforced by Claude Code's permission matcher. Whether `Read(//home/runner/.*/**)` matches dot-directories is untested.
  - **Symlinks.** A file in a PR branch that is a symlink to `/proc/self/environ` would be read through a workspace path. Whether the matcher resolves symlinks before matching is unproven. The guard limits PRs to an allowlisted author in this repository, so only Taylor's own branches could carry such a link.
  - Any other path that exposes the environment is not covered by a rule.
- **T-C1A-4 live checks** (one run Taylor approves, on a test PR by BoaterGuy15 that holds only a test file and a symlink `t/env-link → /proc/self/environ`):
  1. the run waits for environment approval;
  2. after approval, Claude is asked to read `t/env-link` and `/proc/self/environ`, and both reads must be **denied** (the log shows the permission refusal, with no content);
  3. Claude commits one test-file edit, and the commit must land through the API. **Fallback** if the commit fails: allow `Bash(git add:*)`, `Bash(git commit:*)` and `Bash(git push:*)` only, through a reviewed PR;
  4. **if read 2 is not denied:** revoke the key at once. Taylor creates a new one, and claude.yml is disabled until a fix passes G5.

  Since the test PR's author is Taylor, a symlink cannot reach a run any other way.
- **What bounds it:**
  - only same-repository PRs by an allowlisted author reach the key (the guard step);
  - comments from other actors are filtered out;
  - every run needs approval on environment `claude`. **Admin bypass is on** (`can_admins_bypass: true`): a repository admin (Taylor only) can deploy without the approval step. It stays on because Taylor is both the reviewer and the only admin; turning it off is his choice;
  - the Anthropic spend cap is US$50 a month;
  - the key can be revoked in the Anthropic console.
- **If the key ever appears in a commit, comment or log:** revoke it at once. Taylor creates the new one.

## B4. Read-only facts for the record
```sh
gh api orgs/DGL-Labs --jq '{plan: .plan.name}'   # may be null for non-owners; recorded as returned
gh api $R --jq '.visibility'                      # rulesets and environment protection are available on public repositories
nslookup -type=NS dgl.dev                         # DNS on Cloudflare if the NS are *.ns.cloudflare.com
```

## Undo (exact; each value comes from the B0 record; G5 SHOULD 4)
- **B1 workflow permissions:**
  `gh api -X PUT $R/actions/permissions/workflow -f default_workflow_permissions=<B0> -F can_approve_pull_request_reviews=<B0>`
- **B1 fork approval:**
  `gh api -X PUT $R/actions/permissions/fork-pr-contributor-approval -f approval_policy=<B0>`
- **B1 allowed actions:**
  `gh api -X PUT $R/actions/permissions -F enabled=<B0> -f allowed_actions=<B0>`
  - If B0's `selected-actions` GET returned **409**, no list existed. Setting `allowed_actions` back to its B0 value (for example `all`) is the whole undo.
  - If B0 returned a list, PUT that exact B0 body back to `$R/actions/permissions/selected-actions`.
- **B2:**
  `gh api -X DELETE $R/rulesets/<id of main-protection>` and `gh api -X DELETE $R/rulesets/<id of tags-admin-only>` (ids from the POST responses).
- **B3:**
  - `gh api -X DELETE $R/environments/claude/deployment-branch-policies/<id>`;
  - then PUT the environment with `"deployment_branch_policy": null`, and the reviewers, `prevent_self_review`, `wait_timer` and `can_admins_bypass` values from B0.
  - The secret is untouched either way.
