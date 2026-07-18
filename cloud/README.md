# BoundaryCI Cloud control plane

This directory is the first paid-product vertical slice: organization and repository setup, repository-bound ingestion keys, durable scan history, tenant-safe reads, and subscription-aware usage limits.

The scanner remains local. Cloud receives a minimized result only when a customer enables `--upload`; it never needs the customer's database credentials or full migration files.

## Components

- `supabase/migrations/20260718000000_cloud_control_plane.sql` creates organizations, memberships, repositories, hashed ingestion keys, scan runs, findings, indexes, row-level security, onboarding RPCs, and the atomic ingestion RPC.
- `supabase/functions/ingest-scan/index.ts` is the public HTTP boundary. It hashes the bearer token, delegates all authorization and writes to one database transaction, and returns only a scan identifier.
- `../src/cloud.ts` is the CLI payload minimizer and HTTPS upload client.

## Security model

- A plaintext ingestion token is shown once by `create_ingestion_key`; only its SHA-256 hash is stored.
- Every key is bound to one active repository and organization.
- The database verifies that the payload's `owner/repository` matches the key.
- Duplicate `externalId` values return the original run, making retries idempotent.
- Organization members can read only organizations, repositories, runs, and findings for organizations they belong to.
- The ingestion-key table has an explicit deny-all client policy and no authenticated table grants.
- Organization administrators cannot edit plan, subscription, quota, or Stripe fields through client credentials.
- Ingestion stops when a subscription is inactive or its monthly scan allowance is exhausted.
- The Edge Function limits request size and does not expose unexpected database errors.

## Deploy a private-beta environment

Create and link a Supabase project, then apply the migration and deploy the function:

```bash
supabase link --project-ref YOUR_PROJECT_REF
supabase db push
supabase functions deploy ingest-scan --no-verify-jwt
supabase secrets set BOUNDARYCI_APP_URL=https://app.boundaryci.com
```

JWT verification is disabled only at the Edge gateway because uploads use a repository-bound BoundaryCI token instead of a Supabase user JWT. The function authenticates that token through the database RPC. `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are supplied to hosted Supabase Edge Functions; never expose the service-role key to the CLI, browser, or GitHub workflow.

## Onboard an organization

The future dashboard should perform these calls with the signed-in user's Supabase JWT:

1. Call `create_organization(name, slug)`. It creates the organization and its first owner atomically.
2. Insert a `repositories` row for a GitHub `owner/repository`. Row-level security requires an owner or administrator.
3. Call `create_ingestion_key(repository_id, name)`. Display the returned plaintext token once and instruct the user to save it as the GitHub secret `BOUNDARYCI_CLOUD_TOKEN`.
4. Store the Edge Function URL as `BOUNDARYCI_CLOUD_URL` and enable the Action's `upload` input.

Billing webhooks must use a server-side service credential to update `plan`, `subscription_status`, `monthly_scan_limit`, and the Stripe identifiers. Those columns are deliberately not writable by authenticated browser clients. A limit of `0` means unlimited scans and should be reserved for contracted Enterprise accounts.

## Next application slice

Build the authenticated dashboard on these read models:

- organization overview: newest runs, pass rate, and new findings by severity;
- repository page: run history by commit and branch;
- scan page: finding evidence, recommendation, and disposition;
- onboarding: organization, repository, and one-time ingestion-token creation;
- billing: checkout, webhook-driven subscription updates, and usage display.

After five design-partner repositories are sending real runs, prioritize the workflow customers repeatedly request rather than expanding into a generic security dashboard.
