create table if not exists public.access_logs (
  id bigint generated always as identity primary key,
  user_id text not null,
  email text,
  lease_id text,
  ip_address text,
  document_id text,
  created_at timestamptz not null default now()
);

create index if not exists access_logs_user_id_created_at_idx
  on public.access_logs (user_id, created_at desc);

alter table public.access_logs enable row level security;

grant select, insert on public.access_logs to authenticated;
grant select, insert, update, delete on public.access_logs to service_role;
grant usage, select on sequence public.access_logs_id_seq to authenticated, service_role;

create policy "authenticated_read_own_access_logs"
  on public.access_logs
  for select
  to authenticated
  using (user_id = auth.uid()::text or email = (auth.jwt() ->> 'email'));

create policy "authenticated_insert_own_access_logs"
  on public.access_logs
  for insert
  to authenticated
  with check (user_id = auth.uid()::text or email = (auth.jwt() ->> 'email'));
