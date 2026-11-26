create table if not exists public.confidential_documents (
  id bigint generated always as identity primary key,
  slug text not null unique,
  title text not null,
  classification text not null,
  content text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.watermark_records (
  id bigint generated always as identity primary key,
  signature text not null,
  recipient_id text not null,
  session_id text not null,
  owner_id uuid references auth.users (id) on delete set null,
  owner_email text,
  source_type text not null default 'text' check (source_type in ('text', 'pdf_extract', 'pdf_overlay', 'pdf_export', 'stress_demo')),
  filename text,
  chunks_embedded integer not null default 1 check (chunks_embedded >= 0),
  sig_bits text,
  full_bits text,
  created_at timestamptz not null default now()
);

create index if not exists watermark_records_signature_idx on public.watermark_records (signature);
create index if not exists watermark_records_owner_id_idx on public.watermark_records (owner_id);
create index if not exists watermark_records_created_at_idx on public.watermark_records (created_at desc);

create table if not exists public.drm_leases (
  id bigint generated always as identity primary key,
  lease_id text not null unique,
  recipient_id text not null,
  owner_id uuid references auth.users (id) on delete set null,
  owner_email text,
  device_hwid text not null,
  device_fingerprint text not null,
  duration_seconds integer not null check (duration_seconds > 0),
  issued_wall_ts double precision not null,
  expires_at timestamptz not null,
  revoked boolean not null default false,
  tamper_detected boolean not null default false,
  ram_wiped boolean not null default false,
  ram_key_preview text,
  rsa_sig_prefix text,
  document_preview text,
  ciphertext_preview text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists drm_leases_owner_id_idx on public.drm_leases (owner_id);
create index if not exists drm_leases_recipient_id_idx on public.drm_leases (recipient_id);
create index if not exists drm_leases_created_at_idx on public.drm_leases (created_at desc);

create table if not exists public.qr_challenges (
  id bigint generated always as identity primary key,
  challenge_code text not null unique,
  recipient_id text not null,
  owner_id uuid references auth.users (id) on delete set null,
  device_hwid text not null,
  requested_window_sec integer not null check (requested_window_sec > 0),
  nonce text not null,
  consumed boolean not null default false,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists qr_challenges_owner_id_idx on public.qr_challenges (owner_id);
create index if not exists qr_challenges_active_expires_idx on public.qr_challenges (expires_at) where not consumed;

create table if not exists public.leak_inspections (
  id bigint generated always as identity primary key,
  source text not null,
  match_found boolean not null default false,
  verified boolean not null default false,
  recipient_id text,
  session_id text,
  owner_id uuid references auth.users (id) on delete set null,
  owner_email text,
  signature text,
  recovery_mode text,
  chunks_detected integer not null default 0 check (chunks_detected >= 0),
  chunks_verified integer not null default 0 check (chunks_verified >= 0),
  vector_layer_found boolean not null default false,
  homoglyph_trace_detected boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists leak_inspections_owner_id_idx on public.leak_inspections (owner_id);
create index if not exists leak_inspections_created_at_idx on public.leak_inspections (created_at desc);

alter table public.confidential_documents enable row level security;
alter table public.watermark_records enable row level security;
alter table public.drm_leases enable row level security;
alter table public.qr_challenges enable row level security;
alter table public.leak_inspections enable row level security;

grant usage on schema public to anon, authenticated, service_role;

grant select on public.confidential_documents to anon, authenticated;
grant select, insert on public.watermark_records to authenticated;
grant select, insert, update on public.drm_leases to authenticated;
grant select, insert, update on public.qr_challenges to authenticated;
grant select, insert on public.leak_inspections to authenticated;

grant select, insert, update, delete on
  public.confidential_documents,
  public.watermark_records,
  public.drm_leases,
  public.qr_challenges,
  public.leak_inspections
to service_role;

grant usage, select on sequence
  public.confidential_documents_id_seq,
  public.watermark_records_id_seq,
  public.drm_leases_id_seq,
  public.qr_challenges_id_seq,
  public.leak_inspections_id_seq
to authenticated, service_role;

create policy "confidential_documents_public_read"
  on public.confidential_documents
  for select
  to anon, authenticated
  using (true);

create policy "watermark_records_owner_select"
  on public.watermark_records
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "watermark_records_owner_insert"
  on public.watermark_records
  for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "drm_leases_owner_select"
  on public.drm_leases
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "drm_leases_owner_insert"
  on public.drm_leases
  for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "drm_leases_owner_update"
  on public.drm_leases
  for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

create policy "qr_challenges_owner_select"
  on public.qr_challenges
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "qr_challenges_owner_insert"
  on public.qr_challenges
  for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "qr_challenges_owner_update"
  on public.qr_challenges
  for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

create policy "leak_inspections_owner_select"
  on public.leak_inspections
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "leak_inspections_owner_insert"
  on public.leak_inspections
  for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

insert into public.confidential_documents (slug, title, classification, content)
values
  (
    'helios-brief',
    'Project Helios — Executive M&A Valuation Brief',
    'STRICTLY CONFIDENTIAL',
    E'CONFIDENTIAL M&A VALUATION BRIEF: Project Helios buyout ceiling is set at $142M for Q1 2027.\nExecutive committee approval remains strictly embargoed until Monday market open.\nUnauthorized external sharing violates Section 4 NDA terms and triggers immediate revocation.'
  ),
  (
    'security-audit',
    'SentinelTrace — Q4 Zero-Trust Security Audit',
    'INTERNAL RESTRICTED',
    E'CONFIDENTIAL SECURITY AUDIT BRIEF: All ephemeral AES-256-GCM decryption keys rotate via hardware monotonic counters.\nZero plaintext remnants persist to disk across disconnected sessions.\nForensic attribution payloads survive arbitrary snippet truncation above 10% text recovery.'
  ),
  (
    'nda-addendum',
    'Board Committee — Strategic Distribution Addendum',
    'EYES ONLY',
    E'CONFIDENTIAL DISTRIBUTION ADDENDUM: Every distributed copy carries redundant zero-width cryptographic chunks.\nExtracted leak fragments verify against HMAC-SHA256 signatures even after editing.\nRevoked sessions overwrite decryption buffers instantaneously with zeroed byte blocks.'
  )
on conflict (slug) do nothing;
