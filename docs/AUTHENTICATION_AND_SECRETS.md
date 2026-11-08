# Authentication and secrets

Bootstrap is host-local and short lived: `atlas host bootstrap` requires an interactive terminal, generates a random 48-byte token, stores only SHA256 verification material for ten minutes, and becomes unavailable after the first owner exists. Long passphrases use Argon2id (64 MiB, time cost 3, parallelism 2); use at least 15 characters. Benchmark these parameters on the VPS before exposure and increase them when practical. There are no default credentials and no SMS factor.

WebAuthn uses the configured external URL and RP hostname, required user verification, fresh single-use challenges, credential ownership and signature counters. The first passkey must be enrolled soon after sign-in; later additions and removals require recent WebAuthn step-up. TOTP seeds are encrypted; replay counters are checked. Recovery codes are high-entropy, salted Argon2id verifiers and single-use. Production core readiness requires passkeys, TOTP and recovery codes unless the operator explicitly sets ATLAS_PASSKEY_ONLY_RECOVERY=true and maintains offline recovery. Enroll two authenticators.

Server sessions have 30-minute idle and 12-hour absolute limits, opaque token verifiers, revocation and rotation on MFA/step-up. CLI identities are separate scoped tokens. Sensitive CLI scopes expire in five minutes and inherit the recent WebAuthn step-up used to issue them. General tokens expire within seven days. Never use browser session cookies as CLI credentials or store either in localStorage/sessionStorage.

Provider keys and secret headers use random per-secret 256-bit DEKs and unique AES-GCM nonces. The 256-bit KEK wraps each DEK with identity-bound associated data. Postgres stores ciphertext, wrapped DEK, nonces and key version, not plaintext. API responses expose only fingerprints and configuration status. The KEK file must be mode 0400/0600; production fails closed when missing/invalid. TOTP uses a distinct identity-bound envelope. Passwords, session verifiers and provider credentials are separate classes.

## KEK rotation

Stop application/gateway/workers for maintenance. Back up the database encrypted, keep its old KEK separately, and generate a new 32-byte key into a protected file without printing it. The host command `atlas host rotate-kek --new-key-file PATH` transactionally rewraps provider, secret-header and TOTP DEKs; it does not change provider keys. Switch the KEK secret atomically only after that transaction commits, rerun the one-shot Compose initializer to refresh restricted key volumes, then restart and run doctor/provider tests. Keep old KEKs for old encrypted backups; never place KEKs in backup archives. A mismatched/missing key must fail decryption. Losing the KEK can make all protected credentials unrecoverable.

## Recovery

`atlas host break-glass` requires interactive privileged access to the host/application data. It prompts for a new long passphrase, revokes all sessions and CLI tokens, removes authenticators/recovery codes, records an immutable recovery event and forces fresh passkey enrollment. There is no remote equivalent. Protect access to Docker and database volumes as administrative host access.
