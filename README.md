<<<<<<< HEAD
# JanSetu — Government records and welfare MVP

**Assignment:** FT4 · Unit 5 · Application based question and tutorial  
**Use case:** Government blockchain for land records, digital identity and the public distribution system (PDS).

JanSetu is an educational MVP that combines a browser interface, Express API, SQLite datastore and a Solidity contract on a local Hardhat chain. Department users authenticate by signing a one-time wallet challenge. Every write is submitted on-chain by that same local development account; the API checks the contract role and records the actor with the resulting transaction. All seed records and references are synthetic.

> **Demo only.** The app is restricted to loopback and Hardhat chain 31337. It is not deployed to a public or government network. Production startup is deliberately blocked until managed signing, HTTPS, production identity, governance, monitoring and datastore operations are implemented and reviewed.

## What works in the MVP

- Registrar enters parcel ID, owner label, village, area and off-chain document reference.
- Separate land-office and survey-office wallets must approve each parcel.
- Registrar requests an ownership transfer; both distinct departments approve before the contract changes the owner reference.
- Identity issuer can issue and revoke expiring PDS eligibility claims. Welfare operators can verify eligibility and record one monthly delivery receipt.
- Role-gated screens and API routes; signed challenge login; HttpOnly session cookie; CSRF validation; exact-origin checks; request IDs; rate limits; payload validation and idempotency keys.
- Keyed HMAC references on chain; AES-GCM encrypted SQLite rows for demo metadata. Do not use real personal data.
- SQLite transactions/WAL, serialized writes, transaction intents, startup reconciliation and an authenticated transaction-status route.
- Record and audit pagination, health/readiness endpoints, RPC retry/timeout tracking, structured request logs and a persistent light/dark theme.
- Local contract tests and API utility tests.

## Requirements

Use Node.js 22.13 or newer (the API uses the built-in `node:sqlite` module) and npm. From this folder:

```powershell
npm install
npm run compile
npm test
npm run lint
```

## Start the local demo

Open three PowerShell terminals in the project folder.

**Terminal 1 — local blockchain:**

```powershell
npm run chain
```

Keep this terminal open. Hardhat prints development account addresses and private keys. These keys are only for the local chain; never import/use them on a public network.

**Terminal 2 — deploy and seed:**

```powershell
npm run deploy:local
```

The command prints role-to-address mapping and deploys a fresh contract with synthetic records. Redeploy after resetting/restarting the local chain. If you need the local private keys to import the demo roles in MetaMask, open a terminal and run `npm run demo:accounts`. These are public Hardhat test keys; use them only on the local demo network.

**Terminal 3 — application:**

```powershell
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). If this tab was already open, refresh it to load the latest UI and deployment address. The API binds to loopback and refuses to run against a non-Hardhat chain.

### Connect a department operator

1. In MetaMask, add a custom network with RPC `http://127.0.0.1:8545`, chain ID `31337`, and currency `ETH`.
2. Import one of the five private keys printed by the local Hardhat node. Match its address to the mapping printed by `npm run deploy:local`:
   - first account: registrar (also initial contract admin)
   - second account: land office
   - third account: survey office
   - fourth account: identity issuer
   - fifth account: welfare operator
3. In JanSetu, choose **Connect department wallet**, select that account and sign the JanSetu login message. The signature authenticates the account; no account can select another operator’s role through the API.
4. To simulate another department, change the selected MetaMask account and reconnect. Each role has its own visible service screens and permissions.

For an automated local-only login and authorization smoke check, run `npm run smoke:local` while the chain and API are running. It tests each role’s land/PDS read access without submitting workflow transactions.

## Demo sequence

1. **Registrar:** open Land records. Registering a new parcel sends a pending record to the contract.
2. **Land office:** change MetaMask to the land-office account and approve the pending parcel.
3. **Survey office:** switch to the survey-office account and approve it. The second distinct approval changes the contract state to verified.
4. **Registrar:** switch back, open the verified record, and request a transfer to a synthetic owner label.
5. **Land office and survey office:** approve the transfer as separate accounts. The owner reference changes after the second approval.
6. **Identity issuer:** open Digital identity, verify `DEMO-BENEFICIARY-0421`, or issue/revoke a time-limited claim for a synthetic reference.
7. **Welfare operator:** open Welfare register and record a pending delivery. The contract checks current eligibility and prevents a second receipt for the same beneficiary/cycle.
8. **Any authenticated account:** open the audit trail to review workflow actions and transaction hashes.

The theme control in the top bar toggles light and dark mode. The selected theme is saved in browser storage. The interface uses system fonts and does not request Google Fonts.

## Modules

- `public/index.html`, `public/app.js`, `public/styles.css` — responsive role-aware interface, theme toggle, wallet sign-in and workflow screens.
- `server.js` — API routes, role checks, signing adapter, durable intents, reconciliation and operational endpoints.
- `lib/` — auth/session handling, SQLite persistence, privacy helpers, request security, configuration and centralized validation.
- `contracts/LandRegistry.sol` — role governance, land approvals/transfers, expiring eligibility claims and delivery invariants.
- `scripts/deploy.js` — fresh local deployment and synthetic data seeding.
- `scripts/smoke-local.js` — signed local auth and department-access smoke check.
- `test/` — Solidity workflow/governance tests and API utility/persistence tests.

## Deployment boundary and remaining production work

The current signer adapter intentionally supports only local Hardhat accounts. It is **not** a managed signer service. `NODE_ENV=production`, non-loopback binding, nonlocal RPC, and a nonlocal origin cause startup to fail. This keeps the build in local demo/staging preparation and avoids accidentally exposing unlocked accounts.

Before a real staging or production deployment, the next work is to integrate an approved identity provider and managed wallet custody/HSM or multi-party signer, move the service to a supported production database, design key rotation and encrypted backups, configure HTTPS and production origin/CSP, define contract upgrade/admin governance and incident recovery, set audit retention and monitoring, run an independent threat model and contract review, and complete a privacy/legal review. The existing deploy script and seeded accounts are for demonstration only. Do not put private keys or real beneficiary/land records in this repository.

The `JANSETU_HASH_KEY` is an application secret. Local mode generates and ignores `data/demo-hash.key`. Back up the datastore and its key together in a controlled secret/backup process; losing the key makes encrypted metadata unreadable. A production key must come from a secret manager and support planned rotation.

The production dependency audit could not be refreshed in this environment because npm registry DNS/network access failed. Earlier local review found no production dependency advisories and several advisories in the development-only Hardhat 2 toolchain; rerun `npm audit` from a network-enabled environment and plan the Hardhat upgrade before using a shared pipeline.

## Assignment summary

Government offices often hold records in separate systems, making inconsistencies and unauthorized changes difficult to investigate. JanSetu models a shared, permissioned ledger for land registrations, departmental approvals, eligibility claims and PDS delivery receipts. Smart contracts can enforce workflow rules and provide a common audit trail, while they cannot establish that source documents are genuine or replace legal due process. Sensitive records stay off-chain, and residents need accessible ways to inspect and challenge government-held records.
=======

