create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 120),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  plan text not null default 'trial' check (plan in ('trial', 'team', 'growth', 'enterprise')),
  subscription_status text not null default 'trialing'
    check (subscription_status in ('trialing', 'active', 'past_due', 'canceled')),
  monthly_scan_limit integer not null default 100
    check (monthly_scan_limit between 0 and 1000000),
  stripe_customer_id text unique,
  stripe_subscription_id text unique,
  current_period_end timestamptz,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member', 'viewer')),
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

create table public.repositories (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null default 'github' check (provider = 'github'),
  provider_repository_id text,
  full_name text not null check (full_name ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  default_branch text,
  active boolean not null default true,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, provider, full_name),
  unique (id, organization_id)
);

create unique index repositories_org_provider_full_name_lower_idx
  on public.repositories (organization_id, provider, lower(full_name));

create table public.ingestion_keys (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null,
  repository_id uuid not null,
  name text not null check (char_length(name) between 2 and 100),
  key_prefix text not null,
  key_hash text not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  foreign key (repository_id, organization_id)
    references public.repositories(id, organization_id) on delete cascade
);

create table public.scan_runs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null,
  repository_id uuid not null,
  external_id uuid not null,
  provider text not null check (provider = 'github'),
  commit_sha text check (char_length(commit_sha) <= 128),
  branch text check (char_length(branch) <= 255),
  pull_request integer check (pull_request > 0),
  outcome text not null check (outcome in ('passed', 'failed')),
  fail_on text not null check (fail_on in ('critical', 'high', 'medium', 'low', 'none')),
  include_ai_in_exit_code boolean not null,
  tool_version text not null check (char_length(tool_version) <= 40),
  file_count integer not null check (file_count >= 0),
  database_profile jsonb not null check (jsonb_typeof(database_profile) = 'object'),
  semantic_review jsonb not null check (jsonb_typeof(semantic_review) = 'object'),
  summary jsonb not null check (jsonb_typeof(summary) = 'object'),
  scanned_at timestamptz not null,
  received_at timestamptz not null default now(),
  foreign key (repository_id, organization_id)
    references public.repositories(id, organization_id) on delete cascade,
  unique (repository_id, external_id),
  unique (id, organization_id, repository_id)
);

create table public.scan_findings (
  id bigint generated always as identity primary key,
  scan_run_id uuid not null,
  organization_id uuid not null,
  repository_id uuid not null,
  fingerprint text not null check (fingerprint ~ '^[0-9a-f]{24}$'),
  rule_id text not null check (char_length(rule_id) between 2 and 40),
  title text not null check (char_length(title) between 1 and 180),
  description text not null check (char_length(description) <= 1200),
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  confidence text not null check (confidence in ('high', 'medium', 'low')),
  source text not null check (source in ('deterministic', 'fireworks')),
  disposition text not null check (disposition in ('new', 'baseline', 'waived')),
  file_path text not null check (char_length(file_path) between 1 and 500),
  line integer not null check (line > 0),
  evidence text not null check (char_length(evidence) <= 800),
  recommendation text not null check (char_length(recommendation) <= 1200),
  tags jsonb not null default '[]'::jsonb check (jsonb_typeof(tags) = 'array'),
  waiver jsonb check (waiver is null or jsonb_typeof(waiver) = 'object'),
  created_at timestamptz not null default now(),
  foreign key (scan_run_id, organization_id, repository_id)
    references public.scan_runs(id, organization_id, repository_id) on delete cascade,
  unique (scan_run_id, fingerprint)
);

create index scan_runs_repository_received_idx
  on public.scan_runs (repository_id, received_at desc);
create index scan_runs_organization_received_idx
  on public.scan_runs (organization_id, received_at desc);
create index scan_findings_repository_fingerprint_idx
  on public.scan_findings (repository_id, fingerprint, created_at desc);
create index scan_findings_open_severity_idx
  on public.scan_findings (organization_id, severity, created_at desc)
  where disposition = 'new';

alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.repositories enable row level security;
alter table public.ingestion_keys enable row level security;
alter table public.scan_runs enable row level security;
alter table public.scan_findings enable row level security;

create function public.is_organization_member(target_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_members members
    where members.organization_id = target_organization_id
      and members.user_id = auth.uid()
  );
$$;

revoke all on function public.is_organization_member(uuid) from public;
grant execute on function public.is_organization_member(uuid) to authenticated;

create function public.has_organization_role(target_organization_id uuid, allowed_roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.organization_members members
    where members.organization_id = target_organization_id
      and members.user_id = auth.uid()
      and members.role = any (allowed_roles)
  );
$$;

revoke all on function public.has_organization_role(uuid, text[]) from public;
grant execute on function public.has_organization_role(uuid, text[]) to authenticated;

create policy "members can view their organizations"
  on public.organizations
  for select
  to authenticated
  using (public.is_organization_member(id));

create policy "owners and admins can update organization identity"
  on public.organizations
  for update
  to authenticated
  using (public.has_organization_role(id, array['owner', 'admin']))
  with check (public.has_organization_role(id, array['owner', 'admin']));

create policy "members can view organization membership"
  on public.organization_members
  for select
  to authenticated
  using (public.is_organization_member(organization_id));

create policy "members can view repositories"
  on public.repositories
  for select
  to authenticated
  using (public.is_organization_member(organization_id));

create policy "ingestion keys are server managed"
  on public.ingestion_keys
  for all
  to authenticated
  using (false)
  with check (false);

create policy "owners and admins can add repositories"
  on public.repositories
  for insert
  to authenticated
  with check (
    created_by = auth.uid()
    and public.has_organization_role(organization_id, array['owner', 'admin'])
  );

create policy "owners and admins can update repositories"
  on public.repositories
  for update
  to authenticated
  using (public.has_organization_role(organization_id, array['owner', 'admin']))
  with check (public.has_organization_role(organization_id, array['owner', 'admin']));

create policy "owners can remove repositories"
  on public.repositories
  for delete
  to authenticated
  using (public.has_organization_role(organization_id, array['owner']));

create policy "members can view scan runs"
  on public.scan_runs
  for select
  to authenticated
  using (public.is_organization_member(organization_id));

create policy "members can view scan findings"
  on public.scan_findings
  for select
  to authenticated
  using (public.is_organization_member(organization_id));

create function public.create_organization(organization_name text, organization_slug text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  organization_id uuid;
  actor_id uuid := auth.uid();
begin
  if actor_id is null then
    raise exception 'Authentication is required.' using errcode = '28000';
  end if;
  if char_length(trim(organization_name)) not between 2 and 120 then
    raise exception 'Organization name must contain 2 to 120 characters.';
  end if;
  if organization_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$' then
    raise exception 'Organization slug is invalid.';
  end if;

  insert into public.organizations (name, slug, created_by)
  values (trim(organization_name), organization_slug, actor_id)
  returning id into organization_id;

  insert into public.organization_members (organization_id, user_id, role)
  values (organization_id, actor_id, 'owner');

  return organization_id;
end;
$$;

revoke all on function public.create_organization(text, text) from public;
grant execute on function public.create_organization(text, text) to authenticated;

create function public.create_ingestion_key(target_repository_id uuid, key_name text)
returns table (key_id uuid, token text, key_prefix text, created_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  repository_record public.repositories%rowtype;
  plaintext_token text;
begin
  select repositories.*
  into repository_record
  from public.repositories repositories
  where repositories.id = target_repository_id
    and repositories.active;

  if not found or not public.has_organization_role(
    repository_record.organization_id,
    array['owner', 'admin']
  ) then
    raise exception 'Repository was not found.' using errcode = '42501';
  end if;
  if char_length(trim(key_name)) not between 2 and 100 then
    raise exception 'Key name must contain 2 to 100 characters.';
  end if;

  plaintext_token := 'bci_' || translate(
    rtrim(encode(extensions.gen_random_bytes(32), 'base64'), '='),
    '+/',
    '-_'
  );

  return query
  insert into public.ingestion_keys (
    organization_id,
    repository_id,
    name,
    key_prefix,
    key_hash,
    created_by
  )
  values (
    repository_record.organization_id,
    repository_record.id,
    trim(key_name),
    left(plaintext_token, 12),
    encode(extensions.digest(plaintext_token, 'sha256'), 'hex'),
    auth.uid()
  )
  returning ingestion_keys.id, plaintext_token, ingestion_keys.key_prefix, ingestion_keys.created_at;
end;
$$;

revoke all on function public.create_ingestion_key(uuid, text) from public;
grant execute on function public.create_ingestion_key(uuid, text) to authenticated;

create function public.revoke_ingestion_key(target_key_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected_rows integer;
begin
  update public.ingestion_keys keys
  set revoked_at = now()
  where keys.id = target_key_id
    and keys.revoked_at is null
    and public.has_organization_role(keys.organization_id, array['owner', 'admin']);
  get diagnostics affected_rows = row_count;
  return affected_rows = 1;
end;
$$;

revoke all on function public.revoke_ingestion_key(uuid) from public;
grant execute on function public.revoke_ingestion_key(uuid) to authenticated;

create function public.ingest_scan(key_sha256 text, payload jsonb)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  key_record record;
  existing_scan_id uuid;
  new_scan_id uuid;
  external_scan_id uuid;
  finding jsonb;
  scans_this_month integer;
begin
  select
    keys.id as key_id,
    keys.organization_id,
    repositories.id as repository_id,
    repositories.full_name,
    organizations.subscription_status,
    organizations.monthly_scan_limit
  into key_record
  from public.ingestion_keys keys
  join public.repositories repositories
    on repositories.id = keys.repository_id
   and repositories.organization_id = keys.organization_id
  join public.organizations organizations on organizations.id = keys.organization_id
  where keys.key_hash = key_sha256
    and keys.revoked_at is null
    and repositories.active
  for update of organizations;

  if not found then
    raise exception 'Invalid or revoked ingestion token.' using errcode = '28000';
  end if;
  if payload ->> 'schemaVersion' is distinct from '1.0' then
    raise exception 'Unsupported Cloud payload schema.';
  end if;
  if payload ->> 'provider' is distinct from 'github' then
    raise exception 'Unsupported repository provider.';
  end if;
  if lower(payload ->> 'repository') is distinct from lower(key_record.full_name) then
    raise exception 'The token is not valid for this repository.' using errcode = '28000';
  end if;
  if jsonb_typeof(payload -> 'findings') is distinct from 'array' then
    raise exception 'findings must be an array.';
  end if;
  if jsonb_array_length(payload -> 'findings') > 500 then
    raise exception 'A scan cannot contain more than 500 findings.';
  end if;

  external_scan_id := (payload ->> 'externalId')::uuid;
  select runs.id
  into existing_scan_id
  from public.scan_runs runs
  where runs.repository_id = key_record.repository_id
    and runs.external_id = external_scan_id;
  if found then
    return existing_scan_id;
  end if;

  if key_record.subscription_status not in ('trialing', 'active') then
    raise exception 'The BoundaryCI Cloud subscription is not active.';
  end if;

  if key_record.monthly_scan_limit > 0 then
    select count(*)
    into scans_this_month
    from public.scan_runs runs
    where runs.organization_id = key_record.organization_id
      and runs.received_at >= date_trunc('month', now());
    if scans_this_month >= key_record.monthly_scan_limit then
      raise exception 'The monthly scan limit has been reached.';
    end if;
  end if;

  insert into public.scan_runs (
    organization_id,
    repository_id,
    external_id,
    provider,
    commit_sha,
    branch,
    pull_request,
    outcome,
    fail_on,
    include_ai_in_exit_code,
    tool_version,
    file_count,
    database_profile,
    semantic_review,
    summary,
    scanned_at
  )
  values (
    key_record.organization_id,
    key_record.repository_id,
    external_scan_id,
    payload ->> 'provider',
    nullif(payload ->> 'commitSha', ''),
    nullif(payload ->> 'branch', ''),
    nullif(payload ->> 'pullRequest', '')::integer,
    payload ->> 'outcome',
    payload ->> 'failOn',
    (payload ->> 'includeAiInExitCode')::boolean,
    payload ->> 'toolVersion',
    (payload ->> 'fileCount')::integer,
    payload -> 'databaseProfile',
    payload -> 'semanticReview',
    payload -> 'summary',
    (payload ->> 'scannedAt')::timestamptz
  )
  returning id into new_scan_id;

  for finding in select value from jsonb_array_elements(payload -> 'findings')
  loop
    insert into public.scan_findings (
      scan_run_id,
      organization_id,
      repository_id,
      fingerprint,
      rule_id,
      title,
      description,
      severity,
      confidence,
      source,
      disposition,
      file_path,
      line,
      evidence,
      recommendation,
      tags,
      waiver
    )
    values (
      new_scan_id,
      key_record.organization_id,
      key_record.repository_id,
      finding ->> 'fingerprint',
      finding ->> 'ruleId',
      finding ->> 'title',
      finding ->> 'description',
      finding ->> 'severity',
      finding ->> 'confidence',
      finding ->> 'source',
      finding ->> 'disposition',
      finding ->> 'file',
      (finding ->> 'line')::integer,
      finding ->> 'evidence',
      finding ->> 'recommendation',
      coalesce(finding -> 'tags', '[]'::jsonb),
      case when finding -> 'waiver' = 'null'::jsonb then null else finding -> 'waiver' end
    );
  end loop;

  update public.ingestion_keys
  set last_used_at = now()
  where id = key_record.key_id;

  return new_scan_id;
end;
$$;

revoke all on function public.ingest_scan(text, jsonb) from public;
revoke all on function public.ingest_scan(text, jsonb) from anon;
revoke all on function public.ingest_scan(text, jsonb) from authenticated;
grant execute on function public.ingest_scan(text, jsonb) to service_role;

revoke all on table public.ingestion_keys from anon, authenticated;
grant select on table public.organizations to authenticated;
grant update (name, slug) on table public.organizations to authenticated;
grant select on table public.organization_members to authenticated;
grant select, insert, delete on table public.repositories to authenticated;
grant update (full_name, default_branch, active) on table public.repositories to authenticated;
grant select on table public.scan_runs to authenticated;
grant select on table public.scan_findings to authenticated;
