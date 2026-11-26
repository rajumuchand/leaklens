create extension if not exists pg_net;
create extension if not exists pg_cron;

create table if not exists public.service_heartbeats (
  id bigint generated always as identity primary key,
  source text not null,
  status text not null default 'online',
  details text,
  created_at timestamptz not null default now()
);

create index if not exists service_heartbeats_created_at_idx on public.service_heartbeats (created_at desc);

alter table public.service_heartbeats enable row level security;

grant select on public.service_heartbeats to anon, authenticated;
grant select, insert, update, delete on public.service_heartbeats to service_role;
grant usage, select on sequence public.service_heartbeats_id_seq to service_role;

create policy "service_heartbeats_public_read"
  on public.service_heartbeats
  for select
  to anon, authenticated
  using (true);

create or replace function public.record_keepalive_heartbeat()
returns void
language plpgsql
set search_path = ''
as $$
begin
  insert into public.service_heartbeats (source, status, details)
  values ('pg_cron', 'online', 'Scheduled 24/7 keepalive ping');

  perform net.http_get(
    url := 'https://leaklens-omega.vercel.app/api/health',
    timeout_milliseconds := 5000
  );
end;
$$;

do $$
begin
  if exists (select 1 from cron.job where jobname = 'leaklens-24x7-keepalive') then
    perform cron.unschedule('leaklens-24x7-keepalive');
  end if;
  perform cron.schedule(
    'leaklens-24x7-keepalive',
    '0 */4 * * *',
    'select public.record_keepalive_heartbeat();'
  );
end $$;

insert into public.service_heartbeats (source, status, details)
values ('migration', 'online', '24/7 keepalive subsystem initialized');
