-- NATIJ Workspace — database schema (Supabase / Postgres)
-- Tables, row-level security, activity log, notifications and RPCs.

create extension if not exists pgcrypto;

-- ───────────── Settings ─────────────
create table if not exists public.app_settings (
  key text primary key,
  value text not null
);
alter table public.app_settings enable row level security;
-- No policies: only security-definer functions read it.

insert into public.app_settings(key, value)
values ('owner_emails', 'madark1ai@gmail.com')
on conflict (key) do nothing;

-- ───────────── Core tables ─────────────
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null default '',
  is_owner boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 110),
  description text not null default '',
  status text not null default 'active' check (status in ('active','paused')),
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.project_members (
  project_id uuid not null references public.projects(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null default 'member' check (role in ('manager','member')),
  specialty text not null default '',
  created_at timestamptz not null default now(),
  primary key (project_id, user_id)
);
create index if not exists project_members_user_idx on public.project_members(user_id);

create table if not exists public.project_services (
  project_id uuid not null references public.projects(id) on delete cascade,
  service text not null,
  primary key (project_id, service)
);

create table if not exists public.service_templates (
  service text not null,
  position int not null,
  title text not null,
  primary key (service, position)
);
alter table public.service_templates enable row level security;

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  service text not null default '',
  title text not null check (char_length(title) between 3 and 220),
  description text not null default '' check (char_length(description) <= 3000),
  assigned_to uuid references public.profiles(id) on delete set null,
  priority text not null default 'medium' check (priority in ('high','medium','low')),
  status text not null default 'new' check (status in ('new','progress','review','done')),
  due_date date,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);
create index if not exists tasks_project_idx on public.tasks(project_id);
create index if not exists tasks_assigned_idx on public.tasks(assigned_to);

create table if not exists public.task_comments (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.tasks(id) on delete cascade,
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2500),
  created_at timestamptz not null default now()
);
create index if not exists task_comments_task_idx on public.task_comments(task_id);

create table if not exists public.project_invitations (
  code uuid primary key default gen_random_uuid(),
  email text not null,
  project_id uuid not null references public.projects(id) on delete cascade,
  role text not null default 'member' check (role in ('manager','member')),
  specialty text not null default '',
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  accepted_by uuid references public.profiles(id) on delete set null
);
create index if not exists project_invitations_project_idx on public.project_invitations(project_id);

create table if not exists public.activity_log (
  id bigserial primary key,
  project_id uuid references public.projects(id) on delete cascade,
  task_id uuid references public.tasks(id) on delete set null,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists activity_project_idx on public.activity_log(project_id, created_at desc);
create index if not exists activity_task_idx on public.activity_log(task_id);

create table if not exists public.notifications (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  project_id uuid references public.projects(id) on delete cascade,
  task_id uuid references public.tasks(id) on delete cascade,
  title text not null,
  body text not null default '',
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_idx on public.notifications(user_id, created_at desc);

-- ───────────── Permission helpers ─────────────
create or replace function public.is_owner() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_owner from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.is_member(p_project uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.project_members where project_id = p_project and user_id = auth.uid());
$$;

create or replace function public.is_manager(p_project uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_owner() or exists(
    select 1 from public.project_members
    where project_id = p_project and user_id = auth.uid() and role = 'manager');
$$;

create or replace function public.can_access(p_project uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_owner() or public.is_member(p_project);
$$;

create or replace function public.shares_project(p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.project_members a
    join public.project_members b on a.project_id = b.project_id
    where a.user_id = auth.uid() and b.user_id = p_user);
$$;

-- ───────────── New user → profile ─────────────
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare owners text;
begin
  select value into owners from public.app_settings where key = 'owner_emails';
  insert into public.profiles(id, full_name, email, is_owner)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), split_part(new.email, '@', 1)),
    lower(new.email),
    lower(new.email) = any (string_to_array(lower(replace(coalesce(owners, ''), ' ', '')), ','))
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ───────────── Notification + activity helpers ─────────────
create or replace function public.notify_user(p_user uuid, p_project uuid, p_task uuid, p_title text, p_body text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_user is null or p_user = auth.uid() then return; end if;
  insert into public.notifications(user_id, project_id, task_id, title, body)
  values (p_user, p_project, p_task, p_title, coalesce(p_body, ''));
end $$;

create or replace function public.notify_managers(p_project uuid, p_task uuid, p_title text, p_body text)
returns void language plpgsql security definer set search_path = public as $$
declare r record;
begin
  for r in
    select user_id as uid from public.project_members where project_id = p_project and role = 'manager'
    union
    select id from public.profiles where is_owner
  loop
    perform public.notify_user(r.uid, p_project, p_task, p_title, p_body);
  end loop;
end $$;

create or replace function public.stage_label(s text) returns text
language sql immutable set search_path = public as $$
  select case s when 'new' then 'مهام جديدة' when 'progress' then 'قيد التنفيذ'
                when 'review' then 'بانتظار المراجعة' when 'done' then 'مكتملة' else s end;
$$;

-- ───────────── Task rules ─────────────
create or replace function public.tasks_before_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not public.is_manager(old.project_id) then
    -- Assignee may only move status (and never to "done").
    if old.assigned_to is distinct from auth.uid() then
      raise exception 'هذه المهمة ليست مخصصة لك';
    end if;
    if new.title is distinct from old.title or new.description is distinct from old.description
       or new.assigned_to is distinct from old.assigned_to or new.priority is distinct from old.priority
       or new.due_date is distinct from old.due_date or new.service is distinct from old.service
       or new.project_id is distinct from old.project_id then
      raise exception 'تغيير تفاصيل المهمة لمدير المشروع فقط';
    end if;
    if new.status = 'done' and old.status <> 'done' then
      raise exception 'اعتماد المهمة النهائية لمدير المشروع';
    end if;
  end if;
  new.project_id := old.project_id;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;

drop trigger if exists tasks_before_update on public.tasks;
create trigger tasks_before_update before update on public.tasks
  for each row execute function public.tasks_before_update();

create or replace function public.tasks_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.created_by := coalesce(auth.uid(), new.created_by);
  new.updated_by := new.created_by;
  new.created_at := now();
  new.updated_at := now();
  if new.assigned_to is not null and not exists(
       select 1 from public.project_members where project_id = new.project_id and user_id = new.assigned_to) then
    raise exception 'المسؤول يجب أن يكون من فريق المشروع';
  end if;
  return new;
end $$;

drop trigger if exists tasks_before_insert on public.tasks;
create trigger tasks_before_insert before insert on public.tasks
  for each row execute function public.tasks_before_insert();

create or replace function public.tasks_after_change() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.activity_log(project_id, task_id, actor_id, action, details)
    values (new.project_id, new.id, auth.uid(), 'task_created', jsonb_build_object('title', new.title));
    if new.assigned_to is not null then
      perform public.notify_user(new.assigned_to, new.project_id, new.id, 'مهمة جديدة لك', new.title);
    end if;
    return new;
  end if;

  if new.status is distinct from old.status then
    insert into public.activity_log(project_id, task_id, actor_id, action, details)
    values (new.project_id, new.id, auth.uid(), 'status_changed',
            jsonb_build_object('title', new.title, 'from', old.status, 'to', new.status));
    if new.status = 'review' then
      perform public.notify_managers(new.project_id, new.id, 'مهمة بانتظار مراجعتك', new.title);
    elsif new.status = 'done' then
      perform public.notify_user(new.assigned_to, new.project_id, new.id, 'تم اعتماد مهمتك', new.title);
    elsif old.status = 'review' then
      perform public.notify_user(new.assigned_to, new.project_id, new.id, 'أعيدت المهمة إليك: ' || public.stage_label(new.status), new.title);
    end if;
  end if;

  if new.assigned_to is distinct from old.assigned_to then
    insert into public.activity_log(project_id, task_id, actor_id, action, details)
    values (new.project_id, new.id, auth.uid(), 'assigned',
            jsonb_build_object('title', new.title, 'to', new.assigned_to));
    perform public.notify_user(new.assigned_to, new.project_id, new.id, 'أُسندت إليك مهمة', new.title);
  end if;

  if new.due_date is distinct from old.due_date or new.priority is distinct from old.priority
     or new.description is distinct from old.description then
    insert into public.activity_log(project_id, task_id, actor_id, action, details)
    values (new.project_id, new.id, auth.uid(), 'task_edited',
            jsonb_build_object('title', new.title, 'due_date', new.due_date, 'priority', new.priority));
  end if;
  return new;
end $$;

drop trigger if exists tasks_after_change on public.tasks;
create trigger tasks_after_change after insert or update on public.tasks
  for each row execute function public.tasks_after_change();

create or replace function public.tasks_after_delete() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not exists(select 1 from public.projects where id = old.project_id) then return old; end if;
  insert into public.activity_log(project_id, actor_id, action, details)
  values (old.project_id, auth.uid(), 'task_deleted', jsonb_build_object('title', old.title));
  return old;
end $$;

drop trigger if exists tasks_after_delete on public.tasks;
create trigger tasks_after_delete after delete on public.tasks
  for each row execute function public.tasks_after_delete();

-- ───────────── Comments ─────────────
create or replace function public.comments_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
declare t public.tasks;
begin
  select * into t from public.tasks where id = new.task_id;
  insert into public.activity_log(project_id, task_id, actor_id, action, details)
  values (t.project_id, t.id, new.author_id, 'commented',
          jsonb_build_object('title', t.title, 'body', left(new.body, 140)));
  perform public.notify_user(t.assigned_to, t.project_id, t.id, 'تعليق جديد على مهمتك', left(new.body, 140));
  if public.is_member(t.project_id) and not public.is_manager(t.project_id) then
    perform public.notify_managers(t.project_id, t.id, 'تعليق جديد: ' || t.title, left(new.body, 140));
  end if;
  return new;
end $$;

drop trigger if exists comments_after_insert on public.task_comments;
create trigger comments_after_insert after insert on public.task_comments
  for each row execute function public.comments_after_insert();

-- ───────────── Members ─────────────
create or replace function public.members_after_change() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.activity_log(project_id, actor_id, action, details)
    values (new.project_id, new.user_id, 'member_joined', jsonb_build_object('role', new.role, 'specialty', new.specialty));
    return new;
  else
    if not exists(select 1 from public.projects where id = old.project_id) then return old; end if;
    update public.tasks set assigned_to = null where project_id = old.project_id and assigned_to = old.user_id;
    insert into public.activity_log(project_id, actor_id, action, details)
    values (old.project_id, auth.uid(), 'member_removed', jsonb_build_object('user', old.user_id));
    return old;
  end if;
end $$;

drop trigger if exists members_after_change on public.project_members;
create trigger members_after_change after insert or delete on public.project_members
  for each row execute function public.members_after_change();

-- ───────────── RPCs ─────────────
create or replace function public.create_project_from_template(p_name text, p_description text, p_services text[])
returns uuid language plpgsql security definer set search_path = public as $$
declare pid uuid; s text; tpl record;
begin
  if not public.is_owner() then raise exception 'إنشاء المشاريع للمدير العام فقط'; end if;
  if coalesce(trim(p_name), '') = '' or coalesce(array_length(p_services, 1), 0) = 0 then
    raise exception 'أدخل اسم المشروع وحدد خدمة على الأقل';
  end if;
  insert into public.projects(name, description, created_by)
  values (trim(p_name), coalesce(p_description, ''), auth.uid()) returning id into pid;
  foreach s in array p_services loop
    insert into public.project_services(project_id, service) values (pid, s) on conflict do nothing;
    for tpl in select * from public.service_templates where service = s order by position loop
      insert into public.tasks(project_id, service, title, priority, status, due_date)
      values (pid, s, tpl.title, case when tpl.position = 1 then 'high' else 'medium' end, 'new',
              current_date + (tpl.position * 3));
    end loop;
  end loop;
  insert into public.activity_log(project_id, actor_id, action, details)
  values (pid, auth.uid(), 'project_created', jsonb_build_object('name', trim(p_name)));
  return pid;
end $$;

create or replace function public.claim_invitation(p_code uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare inv public.project_invitations; my_email text;
begin
  if auth.uid() is null then raise exception 'سجّل الدخول أولاً'; end if;
  select lower(email) into my_email from auth.users where id = auth.uid();
  select * into inv from public.project_invitations where code = p_code;
  if inv.code is null then raise exception 'الدعوة غير موجودة'; end if;
  if inv.accepted_at is not null then
    return exists(select 1 from public.project_members where project_id = inv.project_id and user_id = auth.uid());
  end if;
  if lower(inv.email) <> my_email then
    raise exception 'هذه الدعوة مرسلة إلى بريد آخر (%)', inv.email;
  end if;
  insert into public.project_members(project_id, user_id, role, specialty)
  values (inv.project_id, auth.uid(), inv.role, inv.specialty)
  on conflict (project_id, user_id) do update set role = excluded.role, specialty = excluded.specialty;
  update public.project_invitations set accepted_at = now(), accepted_by = auth.uid() where code = p_code;
  perform public.notify_user(inv.created_by, inv.project_id, null, 'انضم عضو جديد للمشروع', my_email);
  return true;
end $$;

create or replace function public.mark_notifications_read() returns void
language sql security definer set search_path = public as $$
  update public.notifications set read_at = now() where user_id = auth.uid() and read_at is null;
$$;

-- ───────────── Row-level security ─────────────
alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.project_members enable row level security;
alter table public.project_services enable row level security;
alter table public.tasks enable row level security;
alter table public.task_comments enable row level security;
alter table public.project_invitations enable row level security;
alter table public.activity_log enable row level security;
alter table public.notifications enable row level security;

-- profiles
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or is_owner or public.is_owner() or public.shares_project(id));
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
revoke update on public.profiles from authenticated, anon;
grant update (full_name) on public.profiles to authenticated;

-- projects
drop policy if exists projects_select on public.projects;
create policy projects_select on public.projects for select to authenticated using (public.can_access(id));
drop policy if exists projects_owner_write on public.projects;
create policy projects_owner_write on public.projects for all to authenticated
  using (public.is_owner()) with check (public.is_owner());

-- members
drop policy if exists members_select on public.project_members;
create policy members_select on public.project_members for select to authenticated using (public.can_access(project_id));
drop policy if exists members_owner_write on public.project_members;
create policy members_owner_write on public.project_members for all to authenticated
  using (public.is_owner()) with check (public.is_owner());
drop policy if exists members_manager_remove on public.project_members;
create policy members_manager_remove on public.project_members for delete to authenticated
  using (public.is_manager(project_id) and role = 'member');

-- services
drop policy if exists services_select on public.project_services;
create policy services_select on public.project_services for select to authenticated using (public.can_access(project_id));
drop policy if exists services_owner_write on public.project_services;
create policy services_owner_write on public.project_services for all to authenticated
  using (public.is_owner()) with check (public.is_owner());

-- tasks
drop policy if exists tasks_select on public.tasks;
create policy tasks_select on public.tasks for select to authenticated using (public.can_access(project_id));
drop policy if exists tasks_insert on public.tasks;
create policy tasks_insert on public.tasks for insert to authenticated with check (public.is_manager(project_id));
drop policy if exists tasks_update on public.tasks;
create policy tasks_update on public.tasks for update to authenticated
  using (public.is_manager(project_id) or assigned_to = auth.uid())
  with check (public.can_access(project_id));
drop policy if exists tasks_delete on public.tasks;
create policy tasks_delete on public.tasks for delete to authenticated using (public.is_manager(project_id));

-- comments
drop policy if exists comments_select on public.task_comments;
create policy comments_select on public.task_comments for select to authenticated
  using (exists(select 1 from public.tasks t where t.id = task_id and public.can_access(t.project_id)));
drop policy if exists comments_insert on public.task_comments;
create policy comments_insert on public.task_comments for insert to authenticated
  with check (author_id = auth.uid() and exists(select 1 from public.tasks t where t.id = task_id and public.can_access(t.project_id)));
drop policy if exists comments_delete on public.task_comments;
create policy comments_delete on public.task_comments for delete to authenticated using (author_id = auth.uid());

-- invitations (owner: any; project manager: members of own projects only)
drop policy if exists invites_select on public.project_invitations;
create policy invites_select on public.project_invitations for select to authenticated using (public.is_manager(project_id));
drop policy if exists invites_insert on public.project_invitations;
create policy invites_insert on public.project_invitations for insert to authenticated
  with check (created_by = auth.uid() and public.is_manager(project_id) and (public.is_owner() or role = 'member'));
drop policy if exists invites_delete on public.project_invitations;
create policy invites_delete on public.project_invitations for delete to authenticated
  using (public.is_manager(project_id) and accepted_at is null);

-- activity (read-only, written by triggers)
drop policy if exists activity_select on public.activity_log;
create policy activity_select on public.activity_log for select to authenticated using (public.can_access(project_id));

-- notifications
drop policy if exists notifications_select on public.notifications;
create policy notifications_select on public.notifications for select to authenticated using (user_id = auth.uid());
drop policy if exists notifications_update on public.notifications;
create policy notifications_update on public.notifications for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Function execution: helpers are not meant for anon
revoke execute on function public.create_project_from_template(text, text, text[]) from anon, public;
revoke execute on function public.claim_invitation(uuid) from anon, public;
revoke execute on function public.mark_notifications_read() from anon, public;
revoke execute on function public.notify_user(uuid, uuid, uuid, text, text) from anon, authenticated, public;
revoke execute on function public.notify_managers(uuid, uuid, text, text) from anon, authenticated, public;
revoke execute on function public.handle_new_user() from anon, authenticated, public;
grant execute on function public.create_project_from_template(text, text, text[]) to authenticated;
grant execute on function public.claim_invitation(uuid) to authenticated;
grant execute on function public.mark_notifications_read() to authenticated;
revoke execute on function public.tasks_before_update(), public.tasks_before_insert(), public.tasks_after_change(),
  public.tasks_after_delete(), public.comments_after_insert(), public.members_after_change()
  from anon, authenticated, public;
revoke execute on function public.is_owner(), public.is_member(uuid), public.is_manager(uuid),
  public.can_access(uuid), public.shares_project(uuid) from anon, public;
grant execute on function public.is_owner(), public.is_member(uuid), public.is_manager(uuid),
  public.can_access(uuid), public.shares_project(uuid) to authenticated;

-- ───────────── Service templates ─────────────
insert into public.service_templates(service, position, title) values
 ('Meta Ads',1,'مراجعة الحساب الإعلاني والتتبع'),('Meta Ads',2,'تحليل الجمهور والحملات الحالية'),('Meta Ads',3,'إعداد خطة الاختبار والإطلاق'),('Meta Ads',4,'تقرير الأداء والتحسين الأسبوعي'),
 ('Google Ads',1,'فحص الربط والتحويلات'),('Google Ads',2,'بحث الكلمات والمنتجات ذات الأولوية'),('Google Ads',3,'إعداد حملات Search / Shopping'),('Google Ads',4,'تحسين مصطلحات البحث والأداء'),
 ('SEO',1,'تدقيق SEO الفني للمتجر'),('SEO',2,'تحسين عناوين وتصنيفات المنتجات'),('SEO',3,'مراجعة الفهرسة والروابط الداخلية'),('SEO',4,'تقرير الظهور والزيارات العضوية'),
 ('التحليل والتتبع',1,'تدقيق GA4 وGTM والبيكسلات'),('التحليل والتتبع',2,'اختبار أحداث ViewContent / AddToCart / Purchase'),('التحليل والتتبع',3,'إعداد UTM ومعايير الإسناد'),('التحليل والتتبع',4,'لوحة مؤشرات الأداء والتحقق من البيانات'),
 ('تصميم المتجر',1,'تقييم تجربة المستخدم والصفحة الرئيسية'),('تصميم المتجر',2,'تحسين صفحات المنتج وسهولة الشراء'),('تصميم المتجر',3,'مراجعة سرعة وأداء المتجر على الجوال'),('تصميم المتجر',4,'اختبار مسار الطلب والدفع'),
 ('Snapchat Ads',1,'مراجعة حساب سناب والبيكسل'),('Snapchat Ads',2,'إعداد هيكل الحملات والجماهير'),('Snapchat Ads',3,'اختبار المواد الإعلانية'),('Snapchat Ads',4,'تحسين النتائج ورفع التقرير'),
 ('TikTok Ads',1,'فحص TikTok Pixel والأحداث'),('TikTok Ads',2,'تجهيز خطة زوايا المحتوى'),('TikTok Ads',3,'إطلاق اختبارات المجموعات الإعلانية'),('TikTok Ads',4,'مراجعة CPA وROAS والتحسين'),
 ('إدارة المحتوى',1,'إعداد استراتيجية وركائز المحتوى'),('إدارة المحتوى',2,'تجهيز تقويم النشر'),('إدارة المحتوى',3,'كتابة السكربتات والنصوص والتصاميم'),('إدارة المحتوى',4,'اعتماد ونشر المحتوى وقياس التفاعل')
on conflict do nothing;
