# Known gaps

## C-1b (G5 round 1)

These are accepted for C-1b (G5 round 1). Each has a later task that closes it.

### Timing (SHOULD 3)

`POST /v1/auth/login` gives the same 202 body for known and unknown addresses, but the two paths differ in timing: a known address makes a link and sends an email, an unknown one does not. The send moves to the outbox and worker at C-1f, which removes the difference.

### IPv6 (SHOULD 9)

The sign-up cap and the login and redeem limits count per single IP address. An IPv6 client can rotate through the addresses of its /64 and avoid them. Grouping by /64 comes at C-1g.

### Retention (NOTE 15)

Nothing purges expired `magic_links` and `sessions` yet, nor `signup_events` and `login_failures`, which hold IP addresses (personal data). A retention job comes at C-1g, and the privacy policy must cover these records and how long they are kept.

### Allowlist (NOTE 16)

Sign-up answers 403 for an address that is not on the team allowlist and 202 for one that is, so the status code reveals allowlist membership. This is accepted for the closed alpha, until C-2.

### JWT key (SHOULD 7)

`PINGZO_JWT_KEY` must be random, at least 256 bits, and provided at deploy. The 32-character check in the config loader is a length check, not an entropy check, and does not catch a weak key.

## C-1b (G5 round 2)

1. Link exhaustion: any IP can use up an account's 3 login links per 15 minutes, which voids the pending link. Re-sending sign-up voids an unverified account's verify link, limited only by the per-IP cap. Fix candidate in C-1g: exempt the most recent link from voiding, or a per-account cap plus a cool-off.
2. Shared IP budget: login and redeem share 20 per IP per 15 minutes, so users behind one NAT can lock each other out, and `login_failures` grows by one row per login. Fix candidates in C-1g: separate budgets, IPv6 /64 grouping, retention.
3. Sign-up timing: sign-up for an existing verified email skips the send. This adds to the login timing gap.
4. `PINGZO_JWT_KID` defaults to `k1`. The deploy step (C-1k) must set it deliberately when the key is rotated.
5. Row-level security was not in C-1b. It arrives in C-1c.
6. Default table privileges are unchanged. Each new migration states its grants.

## C-1c

None known. The reviewer should add any gaps found at G5.
