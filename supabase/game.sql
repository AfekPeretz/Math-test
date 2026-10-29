-- ============================================================
--  "בואו נשחק" – database for the math game
--  Paste this whole file into Supabase → SQL Editor → Run.
--  Safe to run again: it only creates what is missing.
--
--  Security model:
--  * Every table has Row Level Security ON and NO policies, and
--    anon/authenticated have no table privileges. Nobody can read
--    or write a table directly with the public (anon) key.
--  * The site can only call the game_* functions below. They check
--    the player's session token, validate every input, and never
--    return PIN hashes or tokens of other players.
--  * PINs and session tokens are stored only as salted SHA-256 hashes.
--  * 5 wrong PINs lock that nickname for 15 minutes.
-- ============================================================

create table if not exists game_groups (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique,
  name        text not null,
  created_at  timestamptz not null default now()
);

create table if not exists game_players (
  id            uuid primary key default gen_random_uuid(),
  group_id      uuid not null references game_groups(id) on delete cascade,
  nickname      text not null,
  avatar        text not null,
  pin_salt      text not null,
  pin_hash      text not null,
  failed        int  not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now()
);
create unique index if not exists game_players_nick on game_players (group_id, lower(nickname));

create table if not exists game_sessions (
  token_hash  text primary key,
  player_id   uuid not null references game_players(id) on delete cascade,
  created_at  timestamptz not null default now(),
  last_seen   timestamptz not null default now()
);

create table if not exists game_rounds (
  id          bigserial primary key,
  player_id   uuid not null references game_players(id) on delete cascade,
  topic       text not null,
  mode        text not null default 'practice',
  correct     int  not null,
  total       int  not null,
  ms          int  not null default 0,
  stars       int  not null default 0,
  xp          int  not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists game_rounds_player on game_rounds (player_id, created_at desc);

create table if not exists game_progress (
  player_id   uuid not null references game_players(id) on delete cascade,
  topic       text not null,
  best_stars  int  not null default 0,
  plays       int  not null default 0,
  primary key (player_id, topic)
);

create table if not exists game_badges (
  player_id   uuid not null references game_players(id) on delete cascade,
  badge       text not null,
  earned_at   timestamptz not null default now(),
  primary key (player_id, badge)
);

create table if not exists game_challenges (
  id          uuid primary key default gen_random_uuid(),
  group_id    uuid not null references game_groups(id) on delete cascade,
  from_player uuid not null references game_players(id) on delete cascade,
  to_player   uuid not null references game_players(id) on delete cascade,
  topic       text not null,
  seed        int  not null,
  from_score  int, from_ms int,
  to_score    int, to_ms   int,
  status      text not null default 'open',
  created_at  timestamptz not null default now()
);
create index if not exists game_challenges_players on game_challenges (from_player, to_player);

alter table game_groups     enable row level security;
alter table game_players    enable row level security;
alter table game_sessions   enable row level security;
alter table game_rounds     enable row level security;
alter table game_progress   enable row level security;
alter table game_badges     enable row level security;
alter table game_challenges enable row level security;

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on game_groups, game_players, game_sessions, game_rounds, game_progress, game_badges, game_challenges from anon';
    execute 'revoke all on sequence game_rounds_id_seq from anon';
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'revoke all on game_groups, game_players, game_sessions, game_rounds, game_progress, game_badges, game_challenges from authenticated';
    execute 'revoke all on sequence game_rounds_id_seq from authenticated';
  end if;
end $$;

-- ---------- internal helpers (not callable from the site) ----------

create or replace function _game_hash(p_salt text, p_value text) returns text
language sql immutable as $$
  select encode(sha256(convert_to(p_salt || ':' || p_value, 'UTF8')), 'hex')
$$;

create or replace function _game_topics() returns text[]
language sql immutable as $$
  select array['mult','distrib','div','addsub','order','numline','divis',
               'fracline','fracvis','fracops','word',
               'lines','tri','quad','area','chart','mix']
$$;

-- Sunday 00:00 of the current week, Israel time
create or replace function _game_week_start() returns timestamptz
language sql stable as $$
  select (((now() at time zone 'Asia/Jerusalem')::date
          - extract(dow from (now() at time zone 'Asia/Jerusalem'))::int)::timestamp)
         at time zone 'Asia/Jerusalem'
$$;

create or replace function _game_player(p_token text) returns game_players
language plpgsql security definer set search_path = public as $$
declare s game_sessions; p game_players;
begin
  if p_token is null or length(p_token) < 20 then raise exception 'bad_token'; end if;
  select * into s from game_sessions where token_hash = _game_hash('session', p_token);
  if not found then raise exception 'bad_token'; end if;
  update game_sessions set last_seen = now() where token_hash = s.token_hash;
  select * into p from game_players where id = s.player_id;
  return p;
end $$;

create or replace function _game_new_session(p_player uuid) returns text
language plpgsql security definer set search_path = public as $$
declare t text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
begin
  insert into game_sessions(token_hash, player_id) values (_game_hash('session', t), p_player);
  -- keep at most 5 sessions (devices) per player
  delete from game_sessions where player_id = p_player and token_hash not in
    (select token_hash from game_sessions where player_id = p_player order by last_seen desc limit 5);
  return t;
end $$;

create or replace function _game_streak(p_player uuid) returns int
language plpgsql stable security definer set search_path = public as $$
declare d date; today date := (now() at time zone 'Asia/Jerusalem')::date; n int := 0; expect date;
begin
  for d in select distinct (created_at at time zone 'Asia/Jerusalem')::date as day
           from game_rounds where player_id = p_player order by day desc loop
    if n = 0 then
      if d < today - 1 then return 0; end if;
      expect := d;
    end if;
    if d = expect then n := n + 1; expect := expect - 1; else exit; end if;
  end loop;
  return n;
end $$;

create or replace function _game_award(p_player uuid, p_badge text, inout p_new text[])
language plpgsql security definer set search_path = public as $$
begin
  insert into game_badges(player_id, badge) values (p_player, p_badge) on conflict do nothing;
  if found then p_new := array_append(p_new, p_badge); end if;
end $$;

create or replace function _game_check_badges(p_player uuid, p_round game_rounds) returns text[]
language plpgsql security definer set search_path = public as $$
declare nb text[] := '{}'; total_xp int; three int; streak int;
begin
  select coalesce(sum(xp),0) into total_xp from game_rounds where player_id = p_player;
  select count(*) into three from game_progress where player_id = p_player and best_stars = 3 and topic <> 'mix';
  streak := _game_streak(p_player);
  nb := _game_award(p_player, 'first_round', nb);
  if p_round.total >= 10 and p_round.correct = p_round.total then nb := _game_award(p_player, 'perfect', nb); end if;
  if p_round.total >= 10 and p_round.ms > 0 and p_round.ms < 60000 and p_round.correct >= p_round.total - 1 then nb := _game_award(p_player, 'speedy', nb); end if;
  if streak >= 3 then nb := _game_award(p_player, 'streak3', nb); end if;
  if streak >= 7 then nb := _game_award(p_player, 'streak7', nb); end if;
  if three >= 3 then nb := _game_award(p_player, 'stars3', nb); end if;
  if three >= 16 then nb := _game_award(p_player, 'all_stars', nb); end if;
  if total_xp >= 500 then nb := _game_award(p_player, 'xp500', nb); end if;
  if total_xp >= 2000 then nb := _game_award(p_player, 'xp2000', nb); end if;
  if (select count(*) from game_progress where player_id = p_player and best_stars = 3
        and topic in ('fracline','fracvis','fracops')) = 3 then nb := _game_award(p_player, 'fractions', nb); end if;
  if (select count(*) from game_progress where player_id = p_player and best_stars = 3
        and topic in ('lines','tri','quad','area')) = 4 then nb := _game_award(p_player, 'geometry', nb); end if;
  return nb;
end $$;

-- records one finished round; the server decides stars and XP
create or replace function _game_record(p_player uuid, p_topic text, p_mode text, p_correct int, p_total int, p_ms int)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r game_rounds; st int; x int; v_last timestamptz; nb text[];
begin
  if not (p_topic = any(_game_topics())) then raise exception 'bad_topic'; end if;
  if p_total is null or p_total < 5 or p_total > 20 then raise exception 'bad_round'; end if;
  if p_correct is null or p_correct < 0 or p_correct > p_total then raise exception 'bad_round'; end if;
  select max(created_at) into v_last from game_rounds where player_id = p_player;
  if v_last is not null and now() - v_last < interval '15 seconds' then raise exception 'too_fast'; end if;
  st := case when p_correct * 10 >= p_total * 9 then 3
             when p_correct * 10 >= p_total * 7 then 2
             when p_correct * 10 >= p_total * 5 then 1 else 0 end;
  x := p_correct * 10 + case when st = 3 then 20 else 0 end;
  insert into game_rounds(player_id, topic, mode, correct, total, ms, stars, xp)
    values (p_player, p_topic, p_mode, p_correct, p_total, greatest(0, least(coalesce(p_ms,0), 3600000)), st, x)
    returning * into r;
  insert into game_progress(player_id, topic, best_stars, plays) values (p_player, p_topic, st, 1)
    on conflict (player_id, topic) do update
    set best_stars = greatest(game_progress.best_stars, excluded.best_stars), plays = game_progress.plays + 1;
  nb := _game_check_badges(p_player, r);
  return jsonb_build_object('stars', st, 'xp', x, 'new_badges', to_jsonb(nb));
end $$;

-- ---------- functions the site calls ----------

create or replace function game_register(p_code text, p_nickname text, p_avatar text, p_pin text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g game_groups; nick text := btrim(coalesce(p_nickname,'')); salt text; pid uuid;
begin
  select * into g from game_groups where upper(code) = upper(btrim(coalesce(p_code,'')));
  if not found then raise exception 'bad_group'; end if;
  if char_length(nick) < 2 or char_length(nick) > 16 or nick ~ '[<>"''&\\/]' then raise exception 'bad_nickname'; end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then raise exception 'bad_pin'; end if;
  if p_avatar is null or char_length(p_avatar) < 1 or char_length(p_avatar) > 8 then raise exception 'bad_avatar'; end if;
  if (select count(*) from game_players where group_id = g.id) >= 80 then raise exception 'group_full'; end if;
  if exists (select 1 from game_players where group_id = g.id and lower(nickname) = lower(nick)) then raise exception 'nick_taken'; end if;
  salt := replace(gen_random_uuid()::text, '-', '');
  insert into game_players(group_id, nickname, avatar, pin_salt, pin_hash)
    values (g.id, nick, p_avatar, salt, _game_hash(salt, p_pin)) returning id into pid;
  return jsonb_build_object('token', _game_new_session(pid));
end $$;

create or replace function game_login(p_code text, p_nickname text, p_pin text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g game_groups; p game_players;
begin
  select * into g from game_groups where upper(code) = upper(btrim(coalesce(p_code,'')));
  if not found then raise exception 'bad_group'; end if;
  select * into p from game_players where group_id = g.id and lower(nickname) = lower(btrim(coalesce(p_nickname,'')));
  if not found then raise exception 'bad_login'; end if;
  if p.locked_until is not null and p.locked_until > now() then return jsonb_build_object('error', 'locked'); end if;
  if p_pin is null or _game_hash(p.pin_salt, p_pin) <> p.pin_hash then
    -- returned, not raised: raising would roll back the failed-attempt count
    if p.failed + 1 >= 5 then
      update game_players set failed = 0, locked_until = now() + interval '15 minutes' where id = p.id;
      return jsonb_build_object('error', 'locked');
    end if;
    update game_players set failed = failed + 1 where id = p.id;
    return jsonb_build_object('error', 'bad_login');
  end if;
  update game_players set failed = 0, locked_until = null where id = p.id;
  return jsonb_build_object('token', _game_new_session(p.id));
end $$;

create or replace function game_logout(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  delete from game_sessions where token_hash = _game_hash('session', coalesce(p_token,''));
  return '{}'::jsonb;
end $$;

create or replace function game_me(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p game_players; g game_groups;
begin
  p := _game_player(p_token);
  select * into g from game_groups where id = p.group_id;
  return jsonb_build_object(
    'id', p.id, 'nickname', p.nickname, 'avatar', p.avatar, 'group', g.name,
    'total_xp', (select coalesce(sum(xp),0) from game_rounds where player_id = p.id),
    'week_xp',  (select coalesce(sum(xp),0) from game_rounds where player_id = p.id and created_at >= _game_week_start()),
    'streak',   _game_streak(p.id),
    'rounds',   (select count(*) from game_rounds where player_id = p.id),
    'progress', (select coalesce(jsonb_object_agg(topic, best_stars), '{}'::jsonb) from game_progress where player_id = p.id),
    'badges',   (select coalesce(jsonb_agg(badge order by earned_at), '[]'::jsonb) from game_badges where player_id = p.id));
end $$;

create or replace function game_submit(p_token text, p_topic text, p_correct int, p_total int, p_ms int)
returns jsonb language plpgsql security definer set search_path = public as $$
declare p game_players;
begin
  p := _game_player(p_token);
  return _game_record(p.id, p_topic, 'practice', p_correct, p_total, p_ms);
end $$;

create or replace function game_leaderboard(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p game_players; ws timestamptz := _game_week_start();
begin
  p := _game_player(p_token);
  return (select coalesce(jsonb_agg(row_to_json(t) order by t.week_xp desc, t.total_xp desc, t.nickname), '[]'::jsonb) from (
    select pl.id, pl.nickname, pl.avatar, (pl.id = p.id) as me,
      coalesce((select sum(xp) from game_rounds r where r.player_id = pl.id and r.created_at >= ws),0) as week_xp,
      coalesce((select sum(xp) from game_rounds r where r.player_id = pl.id),0) as total_xp,
      (select count(*) from game_badges b where b.player_id = pl.id) as badges
    from game_players pl where pl.group_id = p.group_id) t);
end $$;

create or replace function game_challenge_create(p_token text, p_to uuid, p_topic text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare p game_players; o game_players; c game_challenges;
begin
  p := _game_player(p_token);
  if not (p_topic = any(_game_topics())) then raise exception 'bad_topic'; end if;
  select * into o from game_players where id = p_to and group_id = p.group_id;
  if not found or o.id = p.id then raise exception 'bad_opponent'; end if;
  if (select count(*) from game_challenges where from_player = p.id and status = 'open') >= 10 then raise exception 'too_many_open'; end if;
  insert into game_challenges(group_id, from_player, to_player, topic, seed)
    values (p.group_id, p.id, o.id, p_topic, floor(random() * 2000000000)::int) returning * into c;
  return jsonb_build_object('id', c.id, 'seed', c.seed, 'topic', c.topic);
end $$;

create or replace function game_challenge_submit(p_token text, p_id uuid, p_correct int, p_total int, p_ms int)
returns jsonb language plpgsql security definer set search_path = public as $$
declare p game_players; c game_challenges; res jsonb; winner uuid; nb text[] := '{}';
begin
  p := _game_player(p_token);
  select * into c from game_challenges where id = p_id for update;
  if not found or p.id not in (c.from_player, c.to_player) then raise exception 'bad_challenge'; end if;
  if (p.id = c.from_player and c.from_score is not null) or (p.id = c.to_player and c.to_score is not null) then raise exception 'already_played'; end if;
  if p_total <> 10 then raise exception 'bad_round'; end if;
  res := _game_record(p.id, c.topic, 'challenge', p_correct, p_total, p_ms);
  if p.id = c.from_player then
    update game_challenges set from_score = p_correct, from_ms = greatest(0, p_ms) where id = c.id returning * into c;
  else
    update game_challenges set to_score = p_correct, to_ms = greatest(0, p_ms) where id = c.id returning * into c;
  end if;
  if c.from_score is not null and c.to_score is not null then
    winner := case when c.from_score > c.to_score then c.from_player
                   when c.to_score > c.from_score then c.to_player
                   when c.from_ms < c.to_ms then c.from_player
                   when c.to_ms < c.from_ms then c.to_player end;
    update game_challenges set status = 'done' where id = c.id;
    perform _game_award(c.from_player, 'challenger', nb);
    perform _game_award(c.to_player, 'challenger', nb);
    if winner is not null then
      insert into game_rounds(player_id, topic, mode, correct, total, stars, xp) values (winner, c.topic, 'challenge_win', 0, 0, 0, 25);
      perform _game_award(winner, 'winner', nb);
    end if;
  end if;
  return res || jsonb_build_object('status', (select status from game_challenges where id = c.id));
end $$;

create or replace function game_challenges(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare p game_players;
begin
  p := _game_player(p_token);
  return (select coalesce(jsonb_agg(row_to_json(t) order by t.created_at desc), '[]'::jsonb) from (
    select c.id, c.topic, c.seed, c.status, c.created_at,
      (c.from_player = p.id) as mine,
      case when c.from_player = p.id then o2.nickname else o1.nickname end as opponent,
      case when c.from_player = p.id then o2.avatar   else o1.avatar   end as opponent_avatar,
      case when c.from_player = p.id then c.from_score else c.to_score end as my_score,
      case when c.from_player = p.id then c.from_ms    else c.to_ms    end as my_ms,
      -- the opponent's result stays hidden until both have played
      case when c.status = 'done' then (case when c.from_player = p.id then c.to_score else c.from_score end) end as their_score,
      case when c.status = 'done' then (case when c.from_player = p.id then c.to_ms    else c.from_ms    end) end as their_ms,
      ((case when c.from_player = p.id then c.to_score else c.from_score end) is not null) as they_played
    from game_challenges c
    join game_players o1 on o1.id = c.from_player
    join game_players o2 on o2.id = c.to_player
    where p.id in (c.from_player, c.to_player)
    order by c.created_at desc limit 30) t);
end $$;

-- Only the game_* functions are callable from the site; helpers are not.
do $$ declare r text; f text;
  helpers text[] := array['_game_hash(text,text)','_game_topics()','_game_week_start()','_game_player(text)','_game_new_session(uuid)',
                          '_game_streak(uuid)','_game_award(uuid,text,text[])','_game_check_badges(uuid,game_rounds)','_game_record(uuid,text,text,int,int,int)'];
  api text[] := array['game_register(text,text,text,text)','game_login(text,text,text)','game_logout(text)','game_me(text)',
                      'game_submit(text,text,int,int,int)','game_leaderboard(text)','game_challenge_create(text,uuid,text)',
                      'game_challenge_submit(text,uuid,int,int,int)','game_challenges(text)'];
begin
  foreach f in array helpers || api loop execute format('revoke execute on function %s from public', f); end loop;
  foreach r in array array['anon','authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      foreach f in array helpers loop execute format('revoke execute on function %s from %I', f, r); end loop;
      foreach f in array api loop execute format('grant execute on function %s to %I', f, r); end loop;
    end if;
  end loop;
end $$;
