
-- =====================================================
-- شركة السلام | نظام إدارة الأسطول
-- المرحلة الأولى: الجداول والصلاحيات الأساسية
-- =====================================================

create extension if not exists pgcrypto;

-- 1. ملفات المستخدمين المرتبطة بتسجيل الدخول الحقيقي
create table if not exists public.profiles (
    user_id uuid primary key references auth.users(id) on delete cascade,
    full_name text not null,
    role text not null default 'موظف'
        check (role in ('مدير', 'موظف')),
    active boolean not null default true,
    created_at timestamptz not null default now()
);

-- 2. صلاحيات كل موظف
create table if not exists public.user_permissions (
    id bigint generated always as identity primary key,
    user_id uuid not null references public.profiles(user_id) on delete cascade,
    module text not null check (
        module in (
            'dashboard', 'trips', 'overtime', 'fuel',
            'vehicles', 'drivers', 'reports', 'settings'
        )
    ),
    can_view boolean not null default false,
    can_add boolean not null default false,
    can_edit boolean not null default false,
    can_delete boolean not null default false,
    can_print boolean not null default false,
    unique (user_id, module)
);

-- 3. بيانات السيارات
create table if not exists public.vehicles (
    id bigint generated always as identity primary key,
    plate text not null unique,
    kind text not null default '',
    make text not null default '',
    model text not null default '',
    year text not null default '',
    chassis text not null default '',
    engine text not null default '',
    color text not null default '',
    active boolean not null default true,
    created_at timestamptz not null default now()
);

-- 4. بيانات السائقين
create table if not exists public.drivers (
    id bigint generated always as identity primary key,
    name text not null unique,
    active boolean not null default true,
    created_at timestamptz not null default now()
);

-- 5. خطوط السير
create table if not exists public.trips (
    id bigint generated always as identity primary key,
    paper text not null,
    date date not null,
    driver_id bigint references public.drivers(id) on delete restrict,
    vehicle_id bigint references public.vehicles(id) on delete restrict,
    start_time time,
    end_time time,
    start_km numeric(12,2) not null default 0,
    end_km numeric(12,2) not null default 0,
    break_hours numeric(6,2) not null default 0,
    origin text not null default '',
    destination text not null default '',
    deviation numeric(6,2) not null default 0,
    deviation_type text not null default '',
    notes text not null default '',
    status text not null default 'مسجل'
        check (status in ('مسجل', 'معتمد', 'ملغي')),
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    check (start_km >= 0 and end_km >= start_km),
    check (break_hours >= 0 and deviation >= 0)
);

-- 6. أسعار الوقود حسب تاريخ السريان
create table if not exists public.fuel_prices (
    id bigint generated always as identity primary key,
    effective_date date not null,
    fuel_type text not null,
    price numeric(10,2) not null check (price > 0),
    created_at timestamptz not null default now(),
    unique (effective_date, fuel_type)
);

-- 7. التفويلات
create table if not exists public.fuel_records (
    id bigint generated always as identity primary key,
    date date not null,
    driver_id bigint references public.drivers(id) on delete restrict,
    vehicle_id bigint references public.vehicles(id) on delete restrict,
    fuel_type text not null,
    odometer numeric(12,2) not null check (odometer >= 0),
    amount numeric(12,2) not null check (amount > 0),
    price_per_liter numeric(10,2) not null check (price_per_liter > 0),
    liters numeric(12,3) not null check (liters > 0),
    notes text not null default '',
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now()
);

-- 8. إعدادات النظام
create table if not exists public.fleet_settings (
    setting_key text primary key,
    setting_value jsonb not null,
    updated_at timestamptz not null default now()
);

insert into public.fleet_settings(setting_key, setting_value)
values
    ('work_rules', '{"daily_hours": 10, "multi_vehicle_warning": true}'::jsonb)
on conflict (setting_key) do nothing;

-- =====================================================
-- الحماية: دوال التحقق من المستخدم والصلاحية
-- =====================================================

create or replace function public.is_active_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles p
        where p.user_id = (select auth.uid())
          and p.active = true
    );
$$;

create or replace function public.has_permission(
    p_module text,
    p_action text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.profiles p
        where p.user_id = (select auth.uid())
          and p.active = true
          and (
              p.role = 'مدير'
              or exists (
                  select 1
                  from public.user_permissions up
                  where up.user_id = p.user_id
                    and up.module = p_module
                    and case p_action
                        when 'view' then up.can_view
                        when 'add' then up.can_add
                        when 'edit' then up.can_edit
                        when 'delete' then up.can_delete
                        when 'print' then up.can_print
                        else false
                    end
              )
          )
    );
$$;

-- =====================================================
-- تفعيل RLS وإغلاق الوصول غير المصرح به
-- =====================================================

alter table public.profiles enable row level security;
alter table public.user_permissions enable row level security;
alter table public.vehicles enable row level security;
alter table public.drivers enable row level security;
alter table public.trips enable row level security;
alter table public.fuel_prices enable row level security;
alter table public.fuel_records enable row level security;
alter table public.fleet_settings enable row level security;

-- إزالة المنح الافتراضية عن الجداول
revoke all on public.profiles from anon, authenticated;
revoke all on public.user_permissions from anon, authenticated;
revoke all on public.vehicles from anon, authenticated;
revoke all on public.drivers from anon, authenticated;
revoke all on public.trips from anon, authenticated;
revoke all on public.fuel_prices from anon, authenticated;
revoke all on public.fuel_records from anon, authenticated;
revoke all on public.fleet_settings from anon, authenticated;

-- منح صلاحيات SQL الأساسية فقط للمستخدم المسجل
grant select on public.profiles to authenticated;
grant select on public.user_permissions to authenticated;

grant select, insert, update, delete
on public.vehicles, public.drivers, public.trips,
   public.fuel_prices, public.fuel_records, public.fleet_settings
to authenticated;

grant usage, select on all sequences in schema public
to authenticated;

-- الملفات الشخصية: المستخدم يرى ملفه، والمدير يرى الملفات كلها
create policy "profile_read"
on public.profiles for select to authenticated
using (
    user_id = (select auth.uid())
    or public.has_permission('settings', 'view')
);

-- الصلاحيات: المستخدم يرى صلاحياته، والمدير يستطيع عرض الكل
create policy "permissions_read"
on public.user_permissions for select to authenticated
using (
    user_id = (select auth.uid())
    or public.has_permission('settings', 'view')
);

-- السيارات
create policy "vehicles_read"
on public.vehicles for select to authenticated
using (public.has_permission('vehicles', 'view'));

create policy "vehicles_insert"
on public.vehicles for insert to authenticated
with check (public.has_permission('vehicles', 'add'));

create policy "vehicles_update"
on public.vehicles for update to authenticated
using (public.has_permission('vehicles', 'edit'))
with check (public.has_permission('vehicles', 'edit'));

create policy "vehicles_delete"
on public.vehicles for delete to authenticated
using (public.has_permission('vehicles', 'delete'));

-- السائقون
create policy "drivers_read"
on public.drivers for select to authenticated
using (public.has_permission('drivers', 'view'));

create policy "drivers_insert"
on public.drivers for insert to authenticated
with check (public.has_permission('drivers', 'add'));

create policy "drivers_update"
on public.drivers for update to authenticated
using (public.has_permission('drivers', 'edit'))
with check (public.has_permission('drivers', 'edit'));

create policy "drivers_delete"
on public.drivers for delete to authenticated
using (public.has_permission('drivers', 'delete'));

-- خطوط السير
create policy "trips_read"
on public.trips for select to authenticated
using (public.has_permission('trips', 'view'));

create policy "trips_insert"
on public.trips for insert to authenticated
with check (public.has_permission('trips', 'add'));

create policy "trips_update"
on public.trips for update to authenticated
using (public.has_permission('trips', 'edit'))
with check (public.has_permission('trips', 'edit'));

create policy "trips_delete"
on public.trips for delete to authenticated
using (public.has_permission('trips', 'delete'));

-- التفويلات
create policy "fuel_read"
on public.fuel_records for select to authenticated
using (public.has_permission('fuel', 'view'));

create policy "fuel_insert"
on public.fuel_records for insert to authenticated
with check (public.has_permission('fuel', 'add'));

create policy "fuel_update"
on public.fuel_records for update to authenticated
using (public.has_permission('fuel', 'edit'))
with check (public.has_permission('fuel', 'edit'));

create policy "fuel_delete"
on public.fuel_records for delete to authenticated
using (public.has_permission('fuel', 'delete'));

-- أسعار الوقود
create policy "prices_read"
on public.fuel_prices for select to authenticated
using (public.has_permission('fuel', 'view'));

create policy "prices_insert"
on public.fuel_prices for insert to authenticated
with check (public.has_permission('settings', 'edit'));

create policy "prices_update"
on public.fuel_prices for update to authenticated
using (public.has_permission('settings', 'edit'))
with check (public.has_permission('settings', 'edit'));

create policy "prices_delete"
on public.fuel_prices for delete to authenticated
using (public.has_permission('settings', 'edit'));

-- الإعدادات
create policy "settings_read"
on public.fleet_settings for select to authenticated
using (public.has_permission('settings', 'view'));

create policy "settings_insert"
on public.fleet_settings for insert to authenticated
with check (public.has_permission('settings', 'edit'));

create policy "settings_update"
on public.fleet_settings for update to authenticated
using (public.has_permission('settings', 'edit'))
with check (public.has_permission('settings', 'edit'));

create policy "settings_delete"
on public.fleet_settings for delete to authenticated
using (public.has_permission('settings', 'edit'));

-- فهارس لتسريع التقارير والبحث
create index if not exists trips_date_idx
    on public.trips(date);

create index if not exists trips_driver_date_idx
    on public.trips(driver_id, date);

create index if not exists trips_vehicle_date_idx
    on public.trips(vehicle_id, date);

create index if not exists fuel_vehicle_date_idx
    on public.fuel_records(vehicle_id, date);

create index if not exists fuel_driver_date_idx
    on public.fuel_records(driver_id, date);

create index if not exists permissions_user_idx
    on public.user_permissions(user_id);

-- نهاية المرحلة الأولى
