# Pingzo C-1a: repository settings, ruleset and environment (exact calls)

Authority: DIRECT-DGL-COMMS-APP-1-C1-BUILD-GO-1 (Governance a769621), step C-1a only. Plan: C1-PLAN-r4 (619431986112) §6 and §9, with ADDENDUM-1 (0833c15d).
Order: the G5 review covers this file and the pull request. Nothing here is applied before G5 PASS and Taylor's scoped line naming the applier. Every write is preceded by a GET whose output is recorded, so it can be undone.
Repo: `R=repos/DGL-Labs/dgl-comms`. All calls are `gh api` with `-H "X-GitHub-Api-Version: 2022-11-28"` (omitted below for length).
Pinned values come from read-only lookups on 2026-10-16. Their sources are listed in the PR body.

## B0. Record the state before (read-only)
```sh
gh api $R --jq '{visibility, default_branch, owner: .owner.login}'
gh api $R/actions/permissions
gh api $R/actions/permissions/workflow
gh api $R/actions/permissions/selected-actions          # 409 if allowed_actions is not "selected"; recorded as is
gh api $R/actions/permissions/fork-pr-contributor-approval
gh api $R/rulesets
gh api $R/environments/claude
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
- `patterns_allowed` lists `owner/repo@<sha>` for each action in ci.yml and claude.yml, **plus every action that claude-code-action itself uses** (it is a composite action). That list is read from its action.yml at the pinned sha.
- **`workflows` permission.** `GITHUB_TOKEN` has no `workflows` scope. The check is by inspection: no workflow declares `permissions: write-all`, and ci.yml is `contents: read`. The `claude` job has `contents: write` and `pull-requests: write` only. GitHub refuses any `GITHUB_TOKEN` push that changes `.github/workflows/`, so the builder cannot edit workflows.

## B2. Ruleset on the default branch (plan §9)
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
- Actor 5 with type `RepositoryRole` is the Repository admin role. Its `bypass_mode` is `pull_request`, so even the admin cannot push directly. That admin merges through the pull request only.
- There is no bypass for `github-actions` or any app. `integration_id` 15368 is GitHub Actions, so only Actions can satisfy the checks.
- The `pull_request` rule blocks direct pushes, and `non_fast_forward` blocks force pushes.

## B3. Environment `claude`: verify only
Taylor created it, with required reviewer BoaterGuy15 and secret `ANTHROPIC_API_KEY`. **It is not recreated or changed, and the secret is never read or written.**
```sh
gh api $R/environments/claude --jq '{name, protection_rules: [.protection_rules[] | {type, reviewers: [.reviewers[]?.reviewer.login]}], deployment_branch_policy}'
gh api $R/environments/claude/secrets --jq '[.secrets[].name]'   # expect ["ANTHROPIC_API_KEY"]
```
**Recommendation for Taylor (not applied):** restrict the environment's deployment branches to `main`. Comment-triggered runs use the default branch's workflow.

## B4. Read-only facts for the record
```sh
gh api orgs/DGL-Labs --jq '{plan: .plan.name}'   # may be null for non-owners; recorded as returned
gh api $R --jq '.visibility'                      # rulesets and environment protection are available on public repositories
nslookup -type=NS dgl.dev                         # DNS on Cloudflare if the NS are *.ns.cloudflare.com
```

## Undo
- **B1:** PUT back the B0 values.
- **B2:** `gh api -X DELETE $R/rulesets/<id>`.
- **B3:** no change is made.
