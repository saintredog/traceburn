# TraceBurn Security

---

## How PII Is Stored

All personally identifiable information (PII) entered into TraceBurn is encrypted at rest using **AES-256-GCM** before being written to disk.

Key derivation uses **PBKDF2HMAC** with the following parameters:

- Hash: SHA-256
- Iterations: 600,000
- Salt: 32-byte random salt generated per field
- Output key length: 32 bytes (256 bits)

The derived key is held in memory only for the duration of the operation and is **never written to disk**.

### Encrypted Blob Layout

Each encrypted field is stored as a single binary blob with the following layout:

```
[32-byte salt][12-byte nonce][16-byte tag + N-byte ciphertext]
```

- **Salt** (32 bytes): Unique per field. Used with your passphrase to derive the field's encryption key via PBKDF2HMAC.
- **Nonce** (12 bytes): Unique per encryption operation. Required for AES-256-GCM.
- **Tag + Ciphertext** (16 + N bytes): GCM authentication tag prepended to the ciphertext. Decryption will fail and raise an error if the tag does not match, protecting against tampering.

---

## File Permissions

TraceBurn enforces strict filesystem permissions on all data paths at initialization and on each run.

| Path | Permissions | Octal | Why |
|---|---|---|---|
| ~/.traceburn/ | owner rwx only | 700 | Root data dir — private |
| ~/.traceburn/config.yaml | owner rw only | 600 | Config file with non-PII settings |
| ~/.traceburn/traceburn.db | owner rw only | 600 | Encrypted SQLite database |
| ~/.traceburn/proof/ | owner rwx only | 700 | Proof screenshot directory |
| ~/.traceburn/audit.log | owner rw, world r | 644 | Audit log; append-only in practice |
| ~/.traceburn/vault.enc | owner rw only | 600 | Encrypted PII vault |

---

## What TraceBurn Transmits

TraceBurn only makes outbound network requests to execute opt-out form submissions and HTTP requests to data broker websites. It transmits the minimum PII required by each broker's opt-out process (e.g., name and email to confirm removal).

**Nothing else is transmitted.**

---

## What TraceBurn Never Does

- No cloud sync of any data
- No telemetry or usage analytics
- No account creation with third-party services
- No analytics beacons or tracking
- No reporting of your data to any third party

---

## Threat Model

### 1. Physical Device Access

**Threat:** An attacker gains physical or shell access to the machine where TraceBurn data is stored.

**Mitigation:** All PII is encrypted with AES-256-GCM. Without the passphrase, the vault contents are computationally infeasible to recover. File permissions (700/600) also limit access to the owning user account.

---

### 2. Weak Passphrase

**Threat:** The user chooses a weak or guessable passphrase, making brute-force attacks feasible.

**Mitigation:** TraceBurn enforces a passphrase strength check using zxcvbn during `init`. Passphrases that do not meet the minimum strength score are rejected. Additionally, PBKDF2HMAC with 600,000 iterations significantly increases the cost of each brute-force guess, slowing offline attacks even against moderately weak passphrases.

---

### 3. PII in Logs

**Threat:** Debug or audit logs inadvertently capture PII (name, address, phone, email), creating an unencrypted plaintext copy.

**Mitigation:** TraceBurn is designed by default to write no PII to any log file. This holds even when running with `--debug`. Log entries reference record IDs and broker names only.

---

### 4. Malicious Broker Response

**Threat:** A data broker's website returns malicious content (e.g., JavaScript payloads) intended to exploit the automation layer.

**Mitigation:** Playwright runs in a sandboxed browser context. Page content is never passed to `eval()` or executed outside the browser sandbox. TraceBurn only reads specific DOM elements needed to confirm opt-out submission.

---

### 5. Network Interception

**Threat:** An attacker intercepts network traffic between TraceBurn and a broker's opt-out endpoint, capturing PII submitted in form fields.

**Mitigation:** HTTPS is enforced for all opt-out requests. Opt-out URLs are validated to begin with `https://` before any request is made. Plaintext HTTP opt-out URLs are rejected and flagged in the audit log.

---

## Passphrase Warning

Your TraceBurn vault passphrase is **not recoverable**. TraceBurn does not store it, transmit it, or back it up in any form.

- Write your passphrase down and store it in a secure, offline location (e.g., a password manager or physical safe).
- Do not store it in a cloud notes app, email, or any unencrypted file.
- If you lose your passphrase, your vault data cannot be decrypted and will need to be re-entered from scratch.

There is no account recovery, no reset link, and no support team that can recover your passphrase.

---

## Responsible Disclosure

If you discover a security vulnerability in TraceBurn, please report it privately before public disclosure.

**Contact:** security@traceburn.io

Please include a description of the vulnerability, steps to reproduce, and your assessment of impact. We will acknowledge receipt within 48 hours.
