# Known gaps

## C-1b (G5 round 1)

TODO: the original content of `docs/KNOWN-GAPS-C1B.md` must be restored here verbatim from git history (`git show e925a13^:docs/KNOWN-GAPS-C1B.md`). It could not be read in this run, because the run had no shell access.

## C-1b (G5 round 2)

1. Link exhaustion: any IP can use up an account's 3 login links per 15 minutes, which voids the pending link. Re-sending sign-up voids an unverified account's verify link, limited only by the per-IP cap. Fix candidate in C-1g: exempt the most recent link from voiding, or a per-account cap plus a cool-off.
2. Shared IP budget: login and redeem share 20 per IP per 15 minutes, so users behind one NAT can lock each other out, and `login_failures` grows by one row per login. Fix candidates in C-1g: separate budgets, IPv6 /64 grouping, retention.
3. Sign-up timing: sign-up for an existing verified email skips the send. This adds to the login timing gap.
4. `PINGZO_JWT_KID` defaults to `k1`. The deploy step (C-1k) must set it deliberately when the key is rotated.
5. Row-level security was not in C-1b. It arrives in C-1c.
6. Default table privileges are unchanged. Each new migration states its grants.

## C-1c

None recorded yet. The reviewer should add any gaps found at G5.
