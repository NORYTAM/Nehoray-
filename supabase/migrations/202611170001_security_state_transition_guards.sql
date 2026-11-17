-- Security and state-transition hardening for Zivug Mishamayim.
-- The public-profile age/location presentation is intentionally not changed.
-- Apply with: supabase db push
begin;

create or replace function public.guard_profile_owner_write()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_caller_profile_id uuid;
  v_profile_changed boolean;
begin
  -- Trusted Edge Functions and database administrators use the service role.
  if auth.role() = 'service_role' then
    return new;
  end if;

  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  if tg_op = 'INSERT' then
    if new.user_id is distinct from auth.uid() then
      raise exception 'You can only create your own profile' using errcode = '42501';
    end if;

    -- A new profile always starts unapproved; clients cannot self-approve.
    new.status := 'pending';
    new.approved_at := null;
    new.rejection_reason := null;
    new.account_status := coalesce(new.account_status, 'active');
    new.suspension_reason := null;
    new.suspended_until := null;

    if new.role <> 'single' and new.matchmaker_id is not null then
      raise exception 'Only a single profile can select a matchmaker';
    end if;

    if new.matchmaker_id is not null and not exists (
      select 1
      from public.profiles m
      where m.id = new.matchmaker_id
        and m.status = 'approved'
        and m.is_active = true
        and coalesce(m.account_status, 'active') = 'active'
    ) then
      raise exception 'Selected matchmaker is not available';
    end if;

    return new;
  end if;

  if old.user_id is distinct from auth.uid() then
    raise exception 'You can only update your own profile' using errcode = '42501';
  end if;

  if new.id is distinct from old.id or new.user_id is distinct from old.user_id then
    raise exception 'Profile identity fields cannot be changed' using errcode = '42501';
  end if;

  if new.created_at is distinct from old.created_at then
    raise exception 'Profile creation time cannot be changed' using errcode = '42501';
  end if;
  -- The database, not the client device clock, owns the modification timestamp.
  new.updated_at := now();

  if new.approved_at is distinct from old.approved_at
     or new.account_status is distinct from old.account_status
     or new.suspension_reason is distinct from old.suspension_reason
     or new.suspended_until is distinct from old.suspended_until then
    raise exception 'Moderation fields can only be changed by an administrator' using errcode = '42501';
  end if;

  if new.status is distinct from old.status and new.status <> 'pending' then
    raise exception 'Only an administrator can approve or reject a profile' using errcode = '42501';
  end if;

  if old.account_status is distinct from 'active' and new.is_active = true then
    raise exception 'This account cannot be reactivated by its owner' using errcode = '42501';
  end if;

  if new.role <> 'single' and new.matchmaker_id is not null then
    raise exception 'Only a single profile can select a matchmaker';
  end if;

  if new.matchmaker_id is not null and not exists (
    select 1
    from public.profiles m
    where m.id = new.matchmaker_id
      and m.status = 'approved'
      and m.is_active = true
      and coalesce(m.account_status, 'active') = 'active'
  ) then
    raise exception 'Selected matchmaker is not available';
  end if;

  v_profile_changed :=
       new.first_name is distinct from old.first_name
    or new.last_name is distinct from old.last_name
    or new.gender is distinct from old.gender
    or new.role is distinct from old.role
    or new.dob is distinct from old.dob
    or new.bio is distinct from old.bio
    or new.phone is distinct from old.phone
    or new.picture_privacy is distinct from old.picture_privacy
    or new.pictures is distinct from old.pictures
    or new.what_looking_for is distinct from old.what_looking_for
    or new.height is distinct from old.height
    or new.location_city is distinct from old.location_city
    or new.location_state is distinct from old.location_state
    or new.location_country is distinct from old.location_country
    or new.languages is distinct from old.languages
    or new.nationality is distinct from old.nationality
    or new.is_cohen is distinct from old.is_cohen
    or new.hashkafa_type is distinct from old.hashkafa_type
    or new.religious_level is distinct from old.religious_level
    or new.cultural_origin is distinct from old.cultural_origin
    or new.torah_learning is distinct from old.torah_learning
    or new.praying is distinct from old.praying
    or new.education_level is distinct from old.education_level
    or new.post_high_school_path is distinct from old.post_high_school_path
    or new.current_occupation_study is distinct from old.current_occupation_study
    or new.plan_after_marriage is distinct from old.plan_after_marriage
    or new.marital_status is distinct from old.marital_status
    or new.dress_style is distinct from old.dress_style
    or new.wears_black_hat is distinct from old.wears_black_hat
    or new.head_covering is distinct from old.head_covering
    or new.smoking is distinct from old.smoking
    or new.alcohol_consumption is distinct from old.alcohol_consumption
    or new.email is distinct from old.email
    or new.whatsapp is distinct from old.whatsapp
    or new.has_children is distinct from old.has_children
    or new.resume_url is distinct from old.resume_url
    or new.field_privacy is distinct from old.field_privacy
    or new.matchmaker_id is distinct from old.matchmaker_id;

  if new.rejection_reason is distinct from old.rejection_reason
     and not (old.status = 'rejected' and new.status = 'pending' and new.rejection_reason is null) then
    raise exception 'Only an administrator can change the rejection reason' using errcode = '42501';
  end if;

  if v_profile_changed and old.status in ('approved', 'rejected') then
    new.status := 'pending';
    new.rejection_reason := null;
    -- Keep approved_at so moderation can identify an update to a previously
    -- approved profile, rather than treating it as a brand-new profile.
  elsif old.status = 'pending' then
    new.status := 'pending';
    new.rejection_reason := old.rejection_reason;
  end if;

  return new;
end;
$$;

drop trigger if exists profiles_guard_owner_write on public.profiles;
create trigger profiles_guard_owner_write
before insert or update on public.profiles
for each row execute function public.guard_profile_owner_write();

-- All workflow state changes now go through the checked SECURITY DEFINER RPCs
-- below. Read access is unchanged.
revoke insert, update, delete on public.intro_requests from public, anon, authenticated;
revoke insert, update, delete on public.suggestions from public, anon, authenticated;
revoke insert, update, delete on public.info_requests from public, anon, authenticated;
revoke insert, update, delete on public.engagements from public, anon, authenticated;

grant select on public.intro_requests to authenticated;
grant select on public.suggestions to authenticated;
grant select on public.info_requests to authenticated;
grant select on public.engagements to authenticated;

create or replace function public.create_intro_request(
  p_requested_profile_id uuid,
  p_matchmaker_id uuid,
  p_requester_continuation_choice text default null
)
returns public.intro_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_requester public.profiles%rowtype;
  v_requested public.profiles%rowtype;
  v_matchmaker public.profiles%rowtype;
  v_request public.intro_requests%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_requested_profile_id is null or p_matchmaker_id is null then
    raise exception 'Requested profile and matchmaker are required';
  end if;
  if p_requester_continuation_choice is not null
     and p_requester_continuation_choice not in ('by_themselves', 'with_middle_person') then
    raise exception 'Invalid continuation choice';
  end if;

  select * into v_requester from public.profiles
   where user_id = auth.uid() for share;
  if not found then raise exception 'Profile not found'; end if;
  if v_requester.status <> 'approved' or not v_requester.is_active
     or coalesce(v_requester.account_status, 'active') <> 'active' then
    raise exception 'Your profile is not active';
  end if;

  select * into v_requested from public.profiles
   where id = p_requested_profile_id for share;
  if not found or v_requested.status <> 'approved' or not v_requested.is_active
     or coalesce(v_requested.account_status, 'active') <> 'active'
     or v_requested.role <> 'single' then
    raise exception 'Requested profile is not available';
  end if;
  if v_requested.id = v_requester.id then raise exception 'You cannot request yourself'; end if;
  if p_matchmaker_id = v_requester.id or p_matchmaker_id = v_requested.id then
    raise exception 'A match participant cannot be their own matchmaker';
  end if;

  select * into v_matchmaker from public.profiles
   where id = p_matchmaker_id for share;
  if not found or v_matchmaker.status <> 'approved' or not v_matchmaker.is_active
     or coalesce(v_matchmaker.account_status, 'active') <> 'active' then
    raise exception 'Selected matchmaker is not available';
  end if;

  perform pg_advisory_xact_lock(hashtext(v_requester.id::text || ':' || v_requested.id::text));

  if exists (
    select 1 from public.intro_requests
    where requester_id = v_requester.id
      and requested_profile_id = v_requested.id
      and status in ('pending_matchmaker', 'pending_requested', 'accepted')
  ) then
    raise exception 'An active intro request already exists for this profile';
  end if;

  insert into public.intro_requests (
    requester_id, requested_profile_id, requester_middle_person_id,
    requester_continuation_choice, status, matchmaker_status, requested_status
  ) values (
    v_requester.id, v_requested.id, v_matchmaker.id,
    p_requester_continuation_choice, 'pending_matchmaker', 'pending', 'pending'
  ) returning * into v_request;

  return v_request;
end;
$$;

create or replace function public.matchmaker_respond_to_intro_request(
  p_request_id uuid,
  p_response text,
  p_note_to_requester text default null,
  p_note_to_requested text default null
)
returns public.intro_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_request public.intro_requests%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_response not in ('accepted', 'rejected') then raise exception 'Invalid response'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;

  select * into v_request from public.intro_requests where id = p_request_id for update;
  if not found then raise exception 'Request not found'; end if;
  if v_request.requester_middle_person_id <> v_profile_id
     or v_request.status <> 'pending_matchmaker'
     or v_request.matchmaker_status <> 'pending' then
    raise exception 'You are not authorized to respond to this request at its current stage' using errcode = '42501';
  end if;

  update public.intro_requests
     set matchmaker_status = p_response,
         matchmaker_responded_at = now(),
         matchmaker_note_to_requester = case when p_note_to_requester is null then matchmaker_note_to_requester else left(p_note_to_requester, 2000) end,
         matchmaker_note_to_requested = case when p_note_to_requested is null then matchmaker_note_to_requested else left(p_note_to_requested, 2000) end,
         status = case when p_response = 'accepted' then 'pending_requested' else 'rejected' end,
         updated_at = now()
   where id = p_request_id
   returning * into v_request;

  return v_request;
end;
$$;

create or replace function public.requested_person_respond_to_intro_request(
  p_request_id uuid,
  p_response text,
  p_note_to_matchmaker text default null
)
returns public.intro_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_request public.intro_requests%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_response not in ('accepted', 'rejected') then raise exception 'Invalid response'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;

  select * into v_request from public.intro_requests where id = p_request_id for update;
  if not found then raise exception 'Request not found'; end if;
  if v_request.requested_profile_id <> v_profile_id
     or v_request.status <> 'pending_requested'
     or v_request.requested_status <> 'pending' then
    raise exception 'You are not authorized to respond to this request at its current stage' using errcode = '42501';
  end if;

  update public.intro_requests
     set requested_status = p_response,
         requested_responded_at = now(),
         requested_note_to_matchmaker = case when p_note_to_matchmaker is null then requested_note_to_matchmaker else left(p_note_to_matchmaker, 2000) end,
         status = case when p_response = 'accepted' then 'accepted' else 'rejected' end,
         updated_at = now()
   where id = p_request_id
   returning * into v_request;

  return v_request;
end;
$$;

create or replace function public.accept_intro_with_continuation(
  p_request_id uuid,
  p_choice text,
  p_matchmaker_id uuid default null,
  p_note_to_matchmaker text default null
)
returns public.intro_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_request public.intro_requests%rowtype;
  v_selected_matchmaker uuid;
  v_requester_choice text;
  v_requested_choice text;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_choice not in ('by_themselves', 'with_middle_person') then raise exception 'Invalid continuation choice'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;

  select * into v_request from public.intro_requests where id = p_request_id for update;
  if not found then raise exception 'Request not found'; end if;
  if v_request.requested_profile_id <> v_profile_id
     or v_request.status <> 'pending_requested'
     or v_request.matchmaker_status <> 'accepted'
     or v_request.requested_status <> 'pending' then
    raise exception 'You are not authorized to accept this request at its current stage' using errcode = '42501';
  end if;

  v_requester_choice := v_request.requester_continuation_choice;
  v_requested_choice := p_choice;
  v_selected_matchmaker := coalesce(p_matchmaker_id, v_request.requester_middle_person_id);

  if p_choice = 'with_middle_person' or v_requester_choice = 'with_middle_person' then
    if v_selected_matchmaker = v_request.requester_id or v_selected_matchmaker = v_request.requested_profile_id then
      raise exception 'A match participant cannot be their own matchmaker';
    end if;
    v_requester_choice := 'with_middle_person';
    v_requested_choice := 'with_middle_person';
    if not exists (
      select 1 from public.profiles m
      where m.id = v_selected_matchmaker and m.status = 'approved'
        and m.is_active = true and coalesce(m.account_status, 'active') = 'active'
    ) then
      raise exception 'Selected matchmaker is not available';
    end if;
  else
    v_selected_matchmaker := null;
  end if;

  update public.intro_requests
     set requested_status = 'accepted',
         requested_responded_at = now(),
         requested_note_to_matchmaker = case when p_note_to_matchmaker is null then requested_note_to_matchmaker else left(p_note_to_matchmaker, 2000) end,
         requester_continuation_choice = v_requester_choice,
         requested_continuation_choice = v_requested_choice,
         requested_middle_person_id = v_selected_matchmaker,
         status = case when v_requester_choice is not null and v_requested_choice is not null then 'completed' else 'accepted' end,
         updated_at = now()
   where id = p_request_id
   returning * into v_request;

  return v_request;
end;
$$;

create or replace function public.set_intro_continuation_choice(
  p_request_id uuid,
  p_choice text,
  p_matchmaker_id uuid default null
)
returns public.intro_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_request public.intro_requests%rowtype;
  v_selected_matchmaker uuid;
  v_requester_choice text;
  v_requested_choice text;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_choice not in ('by_themselves', 'with_middle_person') then raise exception 'Invalid continuation choice'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;

  select * into v_request from public.intro_requests where id = p_request_id for update;
  if not found then raise exception 'Request not found'; end if;
  if v_request.status <> 'accepted'
     or v_request.matchmaker_status <> 'accepted'
     or v_request.requested_status <> 'accepted' then
    raise exception 'Continuation can only be selected after both sides accept';
  end if;
  if v_request.requester_id <> v_profile_id and v_request.requested_profile_id <> v_profile_id then
    raise exception 'You are not a participant in this request' using errcode = '42501';
  end if;

  v_requester_choice := v_request.requester_continuation_choice;
  v_requested_choice := v_request.requested_continuation_choice;
  v_selected_matchmaker := coalesce(p_matchmaker_id, v_request.requested_middle_person_id, v_request.requester_middle_person_id);

  if v_request.requester_id = v_profile_id then
    v_requester_choice := p_choice;
  else
    v_requested_choice := p_choice;
  end if;

  -- The existing product rule is preserved: if either side chooses a matchmaker,
  -- both sides continue with a matchmaker.
  if p_choice = 'with_middle_person' or v_requester_choice = 'with_middle_person' or v_requested_choice = 'with_middle_person' then
    if v_selected_matchmaker = v_request.requester_id or v_selected_matchmaker = v_request.requested_profile_id then
      raise exception 'A match participant cannot be their own matchmaker';
    end if;
    v_requester_choice := 'with_middle_person';
    v_requested_choice := 'with_middle_person';
    if not exists (
      select 1 from public.profiles m where m.id = v_selected_matchmaker
        and m.status = 'approved' and m.is_active = true
        and coalesce(m.account_status, 'active') = 'active'
    ) then
      raise exception 'Selected matchmaker is not available';
    end if;
  else
    v_selected_matchmaker := null;
  end if;

  update public.intro_requests
     set requester_continuation_choice = v_requester_choice,
         requested_continuation_choice = v_requested_choice,
         requested_middle_person_id = v_selected_matchmaker,
         status = case when v_requester_choice is not null and v_requested_choice is not null then 'completed' else 'accepted' end,
         updated_at = now()
   where id = p_request_id
   returning * into v_request;

  return v_request;
end;
$$;

create or replace function public.create_match_suggestion(
  p_profile_one_id uuid,
  p_profile_two_id uuid,
  p_note text default null,
  p_profile_one_note text default null,
  p_profile_two_note text default null
)
returns public.suggestions
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_suggester public.profiles%rowtype;
  v_profile_one public.profiles%rowtype;
  v_profile_two public.profiles%rowtype;
  v_suggestion public.suggestions%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  select * into v_suggester from public.profiles where user_id = auth.uid();
  if not found or v_suggester.status <> 'approved' or not v_suggester.is_active
     or coalesce(v_suggester.account_status, 'active') <> 'active' then
    raise exception 'An active approved profile is required';
  end if;
  if p_profile_one_id = p_profile_two_id
     or p_profile_one_id = v_suggester.id
     or p_profile_two_id = v_suggester.id then
    raise exception 'You cannot suggest yourself or the same profile twice';
  end if;
  select * into v_profile_one from public.profiles where id = p_profile_one_id;
  if not found or v_profile_one.status <> 'approved' or not v_profile_one.is_active
     or coalesce(v_profile_one.account_status, 'active') <> 'active'
     or v_profile_one.role <> 'single' then
    raise exception 'First profile is not available';
  end if;
  select * into v_profile_two from public.profiles where id = p_profile_two_id;
  if not found or v_profile_two.status <> 'approved' or not v_profile_two.is_active
     or coalesce(v_profile_two.account_status, 'active') <> 'active'
     or v_profile_two.role <> 'single' then
    raise exception 'Second profile is not available';
  end if;

  insert into public.suggestions (
    suggester_id, profile_one_id, profile_two_id, note,
    profile_one_note, profile_two_note,
    profile_one_status, profile_two_status, status
  ) values (
    v_suggester.id, p_profile_one_id, p_profile_two_id,
    left(coalesce(p_note, ''), 2000),
    nullif(left(coalesce(p_profile_one_note, ''), 2000), ''),
    nullif(left(coalesce(p_profile_two_note, ''), 2000), ''),
    'pending', 'pending', 'pending'
  ) returning * into v_suggestion;

  return v_suggestion;
end;
$$;

create or replace function public.respond_to_match_suggestion(
  p_suggestion_id uuid,
  p_response text,
  p_rejection_note text default null
)
returns public.suggestions
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_suggestion public.suggestions%rowtype;
  v_other_status text;
  v_is_one boolean;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_response not in ('accepted', 'rejected') then raise exception 'Invalid response'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;

  select * into v_suggestion from public.suggestions where id = p_suggestion_id for update;
  if not found then raise exception 'Suggestion not found'; end if;
  v_is_one := v_suggestion.profile_one_id = v_profile_id;
  if not v_is_one and v_suggestion.profile_two_id <> v_profile_id then
    raise exception 'You are not part of this suggestion' using errcode = '42501';
  end if;
  if v_suggestion.status = 'rejected' then raise exception 'This suggestion was declined'; end if;
  if (v_is_one and v_suggestion.profile_one_status <> 'pending')
     or (not v_is_one and v_suggestion.profile_two_status <> 'pending') then
    raise exception 'You have already responded to this suggestion';
  end if;

  v_other_status := case when v_is_one then v_suggestion.profile_two_status else v_suggestion.profile_one_status end;
  if v_is_one then
    update public.suggestions
       set profile_one_status = p_response,
           profile_one_rejection_note = case when p_response = 'rejected' then left(coalesce(p_rejection_note, ''), 2000) else null end,
           status = case when p_response = 'rejected' then 'rejected' when v_other_status = 'accepted' then 'accepted' else 'pending' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  else
    update public.suggestions
       set profile_two_status = p_response,
           profile_two_rejection_note = case when p_response = 'rejected' then left(coalesce(p_rejection_note, ''), 2000) else null end,
           status = case when p_response = 'rejected' then 'rejected' when v_other_status = 'accepted' then 'accepted' else 'pending' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  end if;
  return v_suggestion;
end;
$$;

create or replace function public.revert_match_suggestion_rejection(p_suggestion_id uuid)
returns public.suggestions
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_suggestion public.suggestions%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;
  select * into v_suggestion from public.suggestions where id = p_suggestion_id for update;
  if not found then raise exception 'Suggestion not found'; end if;

  if v_suggestion.profile_one_id = v_profile_id and v_suggestion.profile_one_status = 'rejected' then
    update public.suggestions
       set profile_one_status = 'pending',
           profile_one_rejection_note = null,
           status = 'pending',
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  elsif v_suggestion.profile_two_id = v_profile_id and v_suggestion.profile_two_status = 'rejected' then
    update public.suggestions
       set profile_two_status = 'pending',
           profile_two_rejection_note = null,
           status = 'pending',
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  else
    raise exception 'You have not declined this suggestion';
  end if;
  return v_suggestion;
end;
$$;

create or replace function public.accept_match_suggestion_with_continuation(
  p_suggestion_id uuid,
  p_choice text,
  p_middle_person_id uuid default null
)
returns public.suggestions
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_suggestion public.suggestions%rowtype;
  v_other_status text;
  v_other_choice text;
  v_is_one boolean;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_choice not in ('by_themselves', 'with_middle_person') then raise exception 'Invalid continuation choice'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;
  select * into v_suggestion from public.suggestions where id = p_suggestion_id for update;
  if not found then raise exception 'Suggestion not found'; end if;
  v_is_one := v_suggestion.profile_one_id = v_profile_id;
  if not v_is_one and v_suggestion.profile_two_id <> v_profile_id then raise exception 'You are not part of this suggestion' using errcode = '42501'; end if;
  if v_suggestion.status = 'rejected' then raise exception 'This suggestion was declined'; end if;

  if p_choice = 'with_middle_person' and p_middle_person_id is null then
    raise exception 'Choose a matchmaker to continue through a matchmaker';
  end if;
  if p_middle_person_id is not null and (
    p_middle_person_id in (v_suggestion.profile_one_id, v_suggestion.profile_two_id)
    or not exists (
      select 1 from public.profiles m where m.id = p_middle_person_id
        and m.status = 'approved' and m.is_active = true
        and coalesce(m.account_status, 'active') = 'active'
    )
  ) then raise exception 'Selected matchmaker is not available'; end if;

  if v_is_one then
    v_other_status := v_suggestion.profile_two_status;
    v_other_choice := v_suggestion.profile_two_continuation_choice;
    update public.suggestions
       set profile_one_status = 'accepted',
           profile_one_continuation_choice = p_choice,
           profile_one_middle_person_id = case when p_choice = 'with_middle_person' then p_middle_person_id else null end,
           status = case when v_other_status = 'accepted' and v_other_choice is not null then 'completed' else 'accepted' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  else
    v_other_status := v_suggestion.profile_one_status;
    v_other_choice := v_suggestion.profile_one_continuation_choice;
    update public.suggestions
       set profile_two_status = 'accepted',
           profile_two_continuation_choice = p_choice,
           profile_two_middle_person_id = case when p_choice = 'with_middle_person' then p_middle_person_id else null end,
           status = case when v_other_status = 'accepted' and v_other_choice is not null then 'completed' else 'accepted' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  end if;
  return v_suggestion;
end;
$$;

create or replace function public.set_match_suggestion_continuation_choice(
  p_suggestion_id uuid,
  p_choice text,
  p_middle_person_id uuid default null
)
returns public.suggestions
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_suggestion public.suggestions%rowtype;
  v_other_status text;
  v_other_choice text;
  v_is_one boolean;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_choice not in ('by_themselves', 'with_middle_person') then raise exception 'Invalid continuation choice'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;
  select * into v_suggestion from public.suggestions where id = p_suggestion_id for update;
  if not found then raise exception 'Suggestion not found'; end if;
  v_is_one := v_suggestion.profile_one_id = v_profile_id;
  if not v_is_one and v_suggestion.profile_two_id <> v_profile_id then raise exception 'You are not part of this suggestion' using errcode = '42501'; end if;
  if v_suggestion.status = 'rejected' then raise exception 'This suggestion was declined'; end if;
  if p_choice = 'with_middle_person' and p_middle_person_id is null then
    raise exception 'Choose a matchmaker to continue through a matchmaker';
  end if;
  if p_middle_person_id is not null and (
    p_middle_person_id in (v_suggestion.profile_one_id, v_suggestion.profile_two_id)
    or not exists (
      select 1 from public.profiles m where m.id = p_middle_person_id
        and m.status = 'approved' and m.is_active = true
        and coalesce(m.account_status, 'active') = 'active'
    )
  ) then raise exception 'Selected matchmaker is not available'; end if;

  if v_is_one then
    if v_suggestion.profile_one_status <> 'accepted' then raise exception 'You must accept before choosing how to continue'; end if;
    v_other_status := v_suggestion.profile_two_status;
    v_other_choice := v_suggestion.profile_two_continuation_choice;
    update public.suggestions
       set profile_one_continuation_choice = p_choice,
           profile_one_middle_person_id = case when p_choice = 'with_middle_person' then p_middle_person_id else null end,
           status = case when v_other_status = 'accepted' and v_other_choice is not null then 'completed' else 'accepted' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  else
    if v_suggestion.profile_two_status <> 'accepted' then raise exception 'You must accept before choosing how to continue'; end if;
    v_other_status := v_suggestion.profile_one_status;
    v_other_choice := v_suggestion.profile_one_continuation_choice;
    update public.suggestions
       set profile_two_continuation_choice = p_choice,
           profile_two_middle_person_id = case when p_choice = 'with_middle_person' then p_middle_person_id else null end,
           status = case when v_other_status = 'accepted' and v_other_choice is not null then 'completed' else 'accepted' end,
           updated_at = now()
     where id = p_suggestion_id returning * into v_suggestion;
  end if;
  return v_suggestion;
end;
$$;

create or replace function public.create_info_request(
  p_requested_profile_id uuid,
  p_field_name text,
  p_message text
)
returns public.info_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_requester public.profiles%rowtype;
  v_requested public.profiles%rowtype;
  v_request public.info_requests%rowtype;
  v_privacy_key text;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_field_name not in (
    'pictures', 'torahLearning', 'educationLevel', 'hasChildren',
    'torah_learning', 'education_level', 'has_children',
    'height', 'dob', 'phone', 'email', 'whatsapp',
    'location_city', 'location_state', 'location_country',
    'languages', 'nationality', 'is_cohen', 'isCohen',
    'hashkafa_type', 'hashkafaType', 'praying',
    'post_high_school_path', 'postHighSchoolPath',
    'current_occupation_study', 'currentOccupationStudy',
    'plan_after_marriage', 'planAfterMarriage',
    'what_looking_for', 'whatLookingFor',
    'marital_status', 'maritalStatus',
    'dress_style', 'dressStyle',
    'wears_black_hat', 'wearsBlackHat',
    'head_covering', 'headCovering',
    'smoking', 'alcohol_consumption', 'alcoholConsumption'
  ) then
    raise exception 'This information field is not supported';
  end if;
  select * into v_requester from public.profiles where user_id = auth.uid();
  if not found or v_requester.status <> 'approved' or not v_requester.is_active
     or coalesce(v_requester.account_status, 'active') <> 'active' then
    raise exception 'An active approved profile is required';
  end if;
  select * into v_requested from public.profiles where id = p_requested_profile_id;
  if not found or v_requested.status <> 'approved' or not v_requested.is_active
     or coalesce(v_requested.account_status, 'active') <> 'active' then
    raise exception 'Requested profile is not available';
  end if;
  if v_requester.id = v_requested.id then raise exception 'You cannot request information from yourself'; end if;

  if exists (
    select 1 from public.intro_requests r
    where r.status in ('accepted', 'completed')
      and (
        (r.requester_id = v_requester.id and r.requested_profile_id = v_requested.id)
        or (r.requester_id = v_requested.id and r.requested_profile_id = v_requester.id)
      )
  ) or exists (
    select 1 from public.suggestions s
    where s.status in ('accepted', 'completed')
      and (
        (s.profile_one_id = v_requester.id and s.profile_two_id = v_requested.id)
        or (s.profile_one_id = v_requested.id and s.profile_two_id = v_requester.id)
      )
  ) then
    raise exception 'Information requests are not available after a match is accepted';
  end if;

  v_privacy_key := case p_field_name
    when 'location_city' then 'location'
    when 'location_state' then 'location'
    when 'location_country' then 'location'
    when 'is_cohen' then 'isCohen'
    when 'hashkafa_type' then 'hashkafaType'
    when 'post_high_school_path' then 'postHighSchoolPath'
    when 'current_occupation_study' then 'currentOccupationStudy'
    when 'plan_after_marriage' then 'planAfterMarriage'
    when 'what_looking_for' then 'whatLookingFor'
    when 'marital_status' then 'maritalStatus'
    when 'dress_style' then 'dressStyle'
    when 'wears_black_hat' then 'wearsBlackHat'
    when 'head_covering' then 'headCovering'
    when 'alcohol_consumption' then 'alcoholConsumption'
    else p_field_name
  end;

  if p_field_name <> 'pictures'
     and coalesce(v_requested.field_privacy ->> v_privacy_key, v_requested.field_privacy ->> p_field_name, 'false') <> 'true' then
    raise exception 'This field is not marked as private';
  end if;
  if p_field_name = 'pictures' and coalesce(v_requested.picture_privacy, 'none') not in ('private', 'one_time') then
    raise exception 'These pictures are not request-only';
  end if;

  if exists (
    select 1 from public.info_requests
    where requester_id = v_requester.id
      and requested_profile_id = v_requested.id
      and field_name = p_field_name
      and status in ('pending', 'approved')
  ) then raise exception 'An active request for this information already exists'; end if;

  insert into public.info_requests (
    requester_id, requested_profile_id, field_name, message, status
  ) values (
    v_requester.id, v_requested.id, p_field_name, left(coalesce(p_message, ''), 2000), 'pending'
  ) returning * into v_request;
  return v_request;
end;
$$;

create or replace function public.respond_to_info_request(
  p_request_id uuid,
  p_status text
)
returns public.info_requests
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_request public.info_requests%rowtype;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_status not in ('approved', 'rejected') then raise exception 'Invalid response'; end if;
  select id into v_profile_id from public.profiles where user_id = auth.uid();
  if v_profile_id is null then raise exception 'Profile not found'; end if;
  select * into v_request from public.info_requests where id = p_request_id for update;
  if not found then raise exception 'Request not found'; end if;
  if v_request.requested_profile_id <> v_profile_id or v_request.status <> 'pending' then
    raise exception 'You cannot respond to this request' using errcode = '42501';
  end if;
  update public.info_requests
     set status = p_status, responded_at = now()
   where id = p_request_id returning * into v_request;
  return v_request;
end;
$$;

create or replace function public.confirm_engagement(p_other_user_id uuid)
returns public.engagements
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_user1 uuid;
  v_user2 uuid;
  v_engagement public.engagements%rowtype;
  v_is_user1 boolean;
  v_other_confirmed boolean;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_other_user_id is null or p_other_user_id = auth.uid() then raise exception 'Invalid engagement partner'; end if;
  if not exists (
    select 1 from public.profiles p where p.user_id = auth.uid()
      and p.status = 'approved' and p.is_active = true
      and coalesce(p.account_status, 'active') = 'active'
  ) then raise exception 'Your profile is not active'; end if;
  if not exists (
    select 1 from public.profiles p where p.user_id = p_other_user_id
      and p.status = 'approved' and p.is_active = true
      and coalesce(p.account_status, 'active') = 'active'
  ) then raise exception 'The other profile is not available'; end if;

  v_user1 := least(auth.uid(), p_other_user_id);
  v_user2 := greatest(auth.uid(), p_other_user_id);
  perform pg_advisory_xact_lock(hashtext(v_user1::text || ':' || v_user2::text));

  select * into v_engagement from public.engagements
   where user1_id = v_user1 and user2_id = v_user2 for update;

  if not found then
    v_is_user1 := auth.uid() = v_user1;
    insert into public.engagements (
      user1_id, user2_id, user1_confirmed, user2_confirmed, confirmed_at
    ) values (
      v_user1, v_user2, v_is_user1, not v_is_user1, null
    ) returning * into v_engagement;
    return v_engagement;
  end if;

  v_is_user1 := auth.uid() = v_user1;
  if (v_is_user1 and v_engagement.user1_confirmed)
     or (not v_is_user1 and v_engagement.user2_confirmed) then
    raise exception 'You have already confirmed this engagement';
  end if;
  v_other_confirmed := case when v_is_user1 then v_engagement.user2_confirmed else v_engagement.user1_confirmed end;

  if v_is_user1 then
    update public.engagements
       set user1_confirmed = true,
           confirmed_at = case when v_other_confirmed then now() else null end,
           updated_at = now()
     where id = v_engagement.id returning * into v_engagement;
  else
    update public.engagements
       set user2_confirmed = true,
           confirmed_at = case when v_other_confirmed then now() else null end,
           updated_at = now()
     where id = v_engagement.id returning * into v_engagement;
  end if;
  return v_engagement;
end;
$$;

create or replace function public.undo_engagement(p_other_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_user1 uuid;
  v_user2 uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '42501'; end if;
  if p_other_user_id is null or p_other_user_id = auth.uid() then raise exception 'Invalid engagement partner'; end if;
  v_user1 := least(auth.uid(), p_other_user_id);
  v_user2 := greatest(auth.uid(), p_other_user_id);

  delete from public.engagements
   where user1_id = v_user1 and user2_id = v_user2
     and auth.uid() in (user1_id, user2_id);
  return found;
end;
$$;

-- Only authenticated callers may invoke these workflow transitions.
revoke all on function public.create_intro_request(uuid, uuid, text) from public, anon;
revoke all on function public.matchmaker_respond_to_intro_request(uuid, text, text, text) from public, anon;
revoke all on function public.requested_person_respond_to_intro_request(uuid, text, text) from public, anon;
revoke all on function public.accept_intro_with_continuation(uuid, text, uuid, text) from public, anon;
revoke all on function public.set_intro_continuation_choice(uuid, text, uuid) from public, anon;
revoke all on function public.create_match_suggestion(uuid, uuid, text, text, text) from public, anon;
revoke all on function public.respond_to_match_suggestion(uuid, text, text) from public, anon;
revoke all on function public.revert_match_suggestion_rejection(uuid) from public, anon;
revoke all on function public.accept_match_suggestion_with_continuation(uuid, text, uuid) from public, anon;
revoke all on function public.set_match_suggestion_continuation_choice(uuid, text, uuid) from public, anon;
revoke all on function public.create_info_request(uuid, text, text) from public, anon;
revoke all on function public.respond_to_info_request(uuid, text) from public, anon;
revoke all on function public.confirm_engagement(uuid) from public, anon;
revoke all on function public.undo_engagement(uuid) from public, anon;

grant execute on function public.create_intro_request(uuid, uuid, text) to authenticated;
grant execute on function public.matchmaker_respond_to_intro_request(uuid, text, text, text) to authenticated;
grant execute on function public.requested_person_respond_to_intro_request(uuid, text, text) to authenticated;
grant execute on function public.accept_intro_with_continuation(uuid, text, uuid, text) to authenticated;
grant execute on function public.set_intro_continuation_choice(uuid, text, uuid) to authenticated;
grant execute on function public.create_match_suggestion(uuid, uuid, text, text, text) to authenticated;
grant execute on function public.respond_to_match_suggestion(uuid, text, text) to authenticated;
grant execute on function public.revert_match_suggestion_rejection(uuid) to authenticated;
grant execute on function public.accept_match_suggestion_with_continuation(uuid, text, uuid) to authenticated;
grant execute on function public.set_match_suggestion_continuation_choice(uuid, text, uuid) to authenticated;
grant execute on function public.create_info_request(uuid, text, text) to authenticated;
grant execute on function public.respond_to_info_request(uuid, text) to authenticated;
grant execute on function public.confirm_engagement(uuid) to authenticated;
grant execute on function public.undo_engagement(uuid) to authenticated;

comment on function public.create_intro_request(uuid, uuid, text) is 'Creates a participant-bound intro request in the initial pending_matchmaker state.';
comment on function public.matchmaker_respond_to_intro_request(uuid, text, text, text) is 'Allows only the assigned matchmaker to respond once while the request is pending_matchmaker.';
comment on function public.requested_person_respond_to_intro_request(uuid, text, text) is 'Allows only the requested profile to respond once after matchmaker acceptance.';
comment on function public.confirm_engagement(uuid) is 'Atomically creates or confirms an engagement for the authenticated user and the selected partner.';
comment on function public.undo_engagement(uuid) is 'Allows either engagement participant to remove the pair record.';


-- Private profile data is masked in authenticated member reads unless the
-- viewer owns the profile, is an administrator, or the specific info request
-- has been approved. The public-profile share page remains unchanged.
create or replace function public.get_profile_for_viewer(p_profile_id uuid)
returns public.profiles
language plpgsql
stable
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_target public.profiles%rowtype;
  v_viewer_profile_id uuid;
  v_approved_fields text[] := array[]::text[];
  v_is_admin boolean := false;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select * into v_target
  from public.profiles p
  where p.id = p_profile_id;

  if not found then
    return null;
  end if;

  if v_target.user_id = auth.uid() then
    return v_target;
  end if;

  select p.id into v_viewer_profile_id
  from public.profiles p
  where p.user_id = auth.uid();

  select coalesce(array_agg(r.field_name), array[]::text[])
    into v_approved_fields
  from public.info_requests r
  where r.requester_id = v_viewer_profile_id
    and r.requested_profile_id = v_target.id
    and r.status = 'approved';

  select exists (
    select 1 from public.admin_users a where a.user_id = auth.uid()
  ) into v_is_admin;

  if v_is_admin then
    return v_target;
  end if;

  if v_target.status <> 'approved'
     or v_target.is_active is distinct from true
     or coalesce(v_target.account_status, 'active') <> 'active' then
    return null;
  end if;

  -- If the viewer has no profile, no Ask Me fields can be disclosed.
  if v_viewer_profile_id is null then
    v_target.dob := case when coalesce(v_target.field_privacy ->> 'dob', 'false') = 'true' then null else v_target.dob end;
    v_target.what_looking_for := case when coalesce(v_target.field_privacy ->> 'what_looking_for', 'false') = 'true' then null else v_target.what_looking_for end;
    v_target.height := case when coalesce(v_target.field_privacy ->> 'height', 'false') = 'true' then null else v_target.height end;
    v_target.location_city := case when coalesce(v_target.field_privacy ->> 'location', v_target.field_privacy ->> 'location_city', 'false') = 'true' then null else v_target.location_city end;
    v_target.location_state := case when coalesce(v_target.field_privacy ->> 'location', v_target.field_privacy ->> 'location_state', 'false') = 'true' then null else v_target.location_state end;
    v_target.location_country := case when coalesce(v_target.field_privacy ->> 'location', v_target.field_privacy ->> 'location_country', 'false') = 'true' then null else v_target.location_country end;
    v_target.languages := case when coalesce(v_target.field_privacy ->> 'languages', 'false') = 'true' then null else v_target.languages end;
    v_target.nationality := case when coalesce(v_target.field_privacy ->> 'nationality', 'false') = 'true' then null else v_target.nationality end;
    v_target.is_cohen := case when coalesce(v_target.field_privacy ->> 'isCohen', v_target.field_privacy ->> 'is_cohen', 'false') = 'true' then null else v_target.is_cohen end;
    v_target.hashkafa_type := case when coalesce(v_target.field_privacy ->> 'hashkafaType', v_target.field_privacy ->> 'hashkafa_type', 'false') = 'true' then null else v_target.hashkafa_type end;
    v_target.torah_learning := case when coalesce(v_target.field_privacy ->> 'torahLearning', v_target.field_privacy ->> 'torah_learning', 'false') = 'true' then null else v_target.torah_learning end;
    v_target.praying := case when coalesce(v_target.field_privacy ->> 'praying', 'false') = 'true' then null else v_target.praying end;
    v_target.education_level := case when coalesce(v_target.field_privacy ->> 'educationLevel', v_target.field_privacy ->> 'education_level', 'false') = 'true' then null else v_target.education_level end;
    v_target.post_high_school_path := case when coalesce(v_target.field_privacy ->> 'postHighSchoolPath', v_target.field_privacy ->> 'post_high_school_path', 'false') = 'true' then null else v_target.post_high_school_path end;
    v_target.current_occupation_study := case when coalesce(v_target.field_privacy ->> 'currentOccupationStudy', v_target.field_privacy ->> 'current_occupation_study', 'false') = 'true' then null else v_target.current_occupation_study end;
    v_target.plan_after_marriage := case when coalesce(v_target.field_privacy ->> 'planAfterMarriage', v_target.field_privacy ->> 'plan_after_marriage', 'false') = 'true' then null else v_target.plan_after_marriage end;
    v_target.marital_status := case when coalesce(v_target.field_privacy ->> 'maritalStatus', v_target.field_privacy ->> 'marital_status', 'false') = 'true' then null else v_target.marital_status end;
    v_target.dress_style := case when coalesce(v_target.field_privacy ->> 'dressStyle', v_target.field_privacy ->> 'dress_style', 'false') = 'true' then null else v_target.dress_style end;
    v_target.wears_black_hat := case when coalesce(v_target.field_privacy ->> 'wearsBlackHat', v_target.field_privacy ->> 'wears_black_hat', 'false') = 'true' then null else v_target.wears_black_hat end;
    v_target.head_covering := case when coalesce(v_target.field_privacy ->> 'headCovering', v_target.field_privacy ->> 'head_covering', 'false') = 'true' then null else v_target.head_covering end;
    v_target.smoking := case when coalesce(v_target.field_privacy ->> 'smoking', 'false') = 'true' then null else v_target.smoking end;
    v_target.alcohol_consumption := case when coalesce(v_target.field_privacy ->> 'alcoholConsumption', v_target.field_privacy ->> 'alcohol_consumption', 'false') = 'true' then null else v_target.alcohol_consumption end;
    -- Contact details are never part of a general member-profile response.
    v_target.phone := null;
    v_target.email := null;
    v_target.whatsapp := null;
    v_target.has_children := case when coalesce(v_target.field_privacy ->> 'hasChildren', v_target.field_privacy ->> 'has_children', 'false') = 'true' then null else v_target.has_children end;
    v_target.resume_url := null;
    return v_target;
  end if;

  if coalesce(v_target.field_privacy ->> 'dob', 'false') = 'true'
     and not ('dob' = any(v_approved_fields)) then
    v_target.dob := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'what_looking_for', 'false') = 'true'
     and not (v_approved_fields && array['what_looking_for', 'whatLookingFor']::text[]) then
    v_target.what_looking_for := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'height', 'false') = 'true'
     and not ('height' = any(v_approved_fields)) then
    v_target.height := null;
  end if;
  -- Location is a single Ask Me group in the form. Approving any one
  -- location request releases the whole group so the UI never shows a
  -- partial city/state/country combination.
  if (
       coalesce(v_target.field_privacy ->> 'location', 'false') = 'true'
       or coalesce(v_target.field_privacy ->> 'location_city', 'false') = 'true'
       or coalesce(v_target.field_privacy ->> 'location_state', 'false') = 'true'
       or coalesce(v_target.field_privacy ->> 'location_country', 'false') = 'true'
     )
     and not (v_approved_fields && array['location_city', 'location_state', 'location_country']::text[]) then
    v_target.location_city := null;
    v_target.location_state := null;
    v_target.location_country := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'languages', 'false') = 'true'
     and not ('languages' = any(v_approved_fields)) then
    v_target.languages := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'nationality', 'false') = 'true'
     and not ('nationality' = any(v_approved_fields)) then
    v_target.nationality := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'isCohen', v_target.field_privacy ->> 'is_cohen', 'false') = 'true'
     and not (v_approved_fields && array['is_cohen', 'isCohen']::text[]) then
    v_target.is_cohen := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'hashkafaType', v_target.field_privacy ->> 'hashkafa_type', 'false') = 'true'
     and not (v_approved_fields && array['hashkafa_type', 'hashkafaType']::text[]) then
    v_target.hashkafa_type := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'torahLearning', v_target.field_privacy ->> 'torah_learning', 'false') = 'true'
     and not (v_approved_fields && array['torahLearning', 'torah_learning']::text[]) then
    v_target.torah_learning := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'praying', 'false') = 'true'
     and not ('praying' = any(v_approved_fields)) then
    v_target.praying := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'educationLevel', v_target.field_privacy ->> 'education_level', 'false') = 'true'
     and not (v_approved_fields && array['educationLevel', 'education_level']::text[]) then
    v_target.education_level := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'postHighSchoolPath', v_target.field_privacy ->> 'post_high_school_path', 'false') = 'true'
     and not (v_approved_fields && array['post_high_school_path', 'postHighSchoolPath']::text[]) then
    v_target.post_high_school_path := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'currentOccupationStudy', v_target.field_privacy ->> 'current_occupation_study', 'false') = 'true'
     and not (v_approved_fields && array['current_occupation_study', 'currentOccupationStudy']::text[]) then
    v_target.current_occupation_study := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'planAfterMarriage', v_target.field_privacy ->> 'plan_after_marriage', 'false') = 'true'
     and not (v_approved_fields && array['plan_after_marriage', 'planAfterMarriage']::text[]) then
    v_target.plan_after_marriage := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'maritalStatus', v_target.field_privacy ->> 'marital_status', 'false') = 'true'
     and not (v_approved_fields && array['marital_status', 'maritalStatus']::text[]) then
    v_target.marital_status := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'dressStyle', v_target.field_privacy ->> 'dress_style', 'false') = 'true'
     and not (v_approved_fields && array['dress_style', 'dressStyle']::text[]) then
    v_target.dress_style := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'wearsBlackHat', v_target.field_privacy ->> 'wears_black_hat', 'false') = 'true'
     and not (v_approved_fields && array['wears_black_hat', 'wearsBlackHat']::text[]) then
    v_target.wears_black_hat := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'headCovering', v_target.field_privacy ->> 'head_covering', 'false') = 'true'
     and not (v_approved_fields && array['head_covering', 'headCovering']::text[]) then
    v_target.head_covering := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'smoking', 'false') = 'true'
     and not ('smoking' = any(v_approved_fields)) then
    v_target.smoking := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'alcoholConsumption', v_target.field_privacy ->> 'alcohol_consumption', 'false') = 'true'
     and not (v_approved_fields && array['alcohol_consumption', 'alcoholConsumption']::text[]) then
    v_target.alcohol_consumption := null;
  end if;
  -- Contact details are not returned by general profile reads. A completed
  -- workflow may reveal them through get_workflow_contact_profiles instead.
  if not ('phone' = any(v_approved_fields)) then
    v_target.phone := null;
  end if;
  if not ('email' = any(v_approved_fields)) then
    v_target.email := null;
  end if;
  if not ('whatsapp' = any(v_approved_fields)) then
    v_target.whatsapp := null;
  end if;
  if coalesce(v_target.field_privacy ->> 'hasChildren', v_target.field_privacy ->> 'has_children', 'false') = 'true'
     and not (v_approved_fields && array['hasChildren', 'has_children']::text[]) then
    v_target.has_children := null;
  end if;

  -- Résumés remain private unless a dedicated request has been approved.
  if not (v_approved_fields && array['resume', 'resume_url', 'resumeUrl']::text[]) then
    v_target.resume_url := null;
  end if;

  return v_target;
end;
$$;

create or replace function public.get_directory_profiles()
returns setof public.profiles
language plpgsql
stable
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_profile_id uuid;
  v_admin boolean := false;
  v_row record;
  v_visible public.profiles%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select exists (
    select 1 from public.admin_users a where a.user_id = auth.uid()
  ) into v_admin;

  for v_row in
    select p.id
    from public.profiles p
    where p.status = 'approved'
      and p.is_active = true
      and coalesce(p.account_status, 'active') = 'active'
      and p.role = 'single'
      and not exists (
        select 1 from public.admin_users a where a.user_id = p.user_id
      )
    order by p.created_at desc
  loop
    v_visible := public.get_profile_for_viewer(v_row.id);
    if v_visible.id is not null then
      return next v_visible;
    end if;
  end loop;

  return;
end;
$$;

revoke all on function public.get_profile_for_viewer(uuid) from public, anon;
revoke all on function public.get_directory_profiles() from public, anon;
grant execute on function public.get_profile_for_viewer(uuid) to authenticated;
grant execute on function public.get_directory_profiles() to authenticated;


-- Return contact details only to participants or the selected matchmaker and
-- only after both parties accepted and completed their continuation choices.
create or replace function public.get_workflow_contact_profiles(
  p_workflow_type text,
  p_workflow_id uuid
)
returns table(
  profile_id uuid,
  first_name text,
  last_name text,
  phone text,
  email text,
  whatsapp text,
  resume_url text
)
language plpgsql
security definer
set search_path = public, pg_temp
set row_security = off
as $$
declare
  v_viewer_profile_id uuid;
  v_intro public.intro_requests%rowtype;
  v_suggestion public.suggestions%rowtype;
  v_contact_id uuid;
  v_is_with_matchmaker boolean;
  v_one_with_matchmaker boolean;
  v_two_with_matchmaker boolean;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select p.id into v_viewer_profile_id
  from public.profiles p
  where p.user_id = auth.uid();

  if v_viewer_profile_id is null then
    raise exception 'Profile not found';
  end if;

  if p_workflow_type = 'intro' then
    select * into v_intro
    from public.intro_requests r
    where r.id = p_workflow_id;

    if not found
       or v_intro.status not in ('accepted', 'completed')
       or v_intro.matchmaker_status <> 'accepted'
       or v_intro.requested_status <> 'accepted'
       or v_intro.requester_continuation_choice is null
       or v_intro.requested_continuation_choice is null then
      return;
    end if;

    v_is_with_matchmaker :=
      v_intro.requester_continuation_choice = 'with_middle_person'
      or v_intro.requested_continuation_choice = 'with_middle_person';

    if v_is_with_matchmaker then
      v_contact_id := coalesce(v_intro.requested_middle_person_id, v_intro.requester_middle_person_id);
      if v_contact_id is null then
        return;
      end if;

      -- The participants may see the selected matchmaker's contact details.
      if v_viewer_profile_id in (v_intro.requester_id, v_intro.requested_profile_id) then
        return query
          select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
          from public.profiles p
          where p.id = v_contact_id;
        return;
      end if;

      -- Only the selected matchmaker may see both participants' contact details.
      if v_viewer_profile_id = v_contact_id then
        return query
          select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
          from public.profiles p
          where p.id in (v_intro.requester_id, v_intro.requested_profile_id)
          order by case when p.id = v_intro.requester_id then 0 else 1 end;
        return;
      end if;

      return;
    end if;

    -- Direct contact is available only when both selected to continue directly.
    if v_intro.requester_continuation_choice = 'by_themselves'
       and v_intro.requested_continuation_choice = 'by_themselves' then
      if v_viewer_profile_id = v_intro.requester_id then
        v_contact_id := v_intro.requested_profile_id;
      elsif v_viewer_profile_id = v_intro.requested_profile_id then
        v_contact_id := v_intro.requester_id;
      else
        return;
      end if;

      return query
        select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
        from public.profiles p
        where p.id = v_contact_id;
      return;
    end if;

    return;
  elsif p_workflow_type = 'suggestion' then
    select * into v_suggestion
    from public.suggestions s
    where s.id = p_workflow_id;

    if not found
       or v_suggestion.status not in ('accepted', 'completed')
       or v_suggestion.profile_one_status <> 'accepted'
       or v_suggestion.profile_two_status <> 'accepted'
       or v_suggestion.profile_one_continuation_choice is null
       or v_suggestion.profile_two_continuation_choice is null then
      return;
    end if;

    v_one_with_matchmaker := v_suggestion.profile_one_continuation_choice = 'with_middle_person';
    v_two_with_matchmaker := v_suggestion.profile_two_continuation_choice = 'with_middle_person';
    v_is_with_matchmaker := v_one_with_matchmaker or v_two_with_matchmaker;

    if v_is_with_matchmaker then
      -- A participant sees the chosen matchmaker that will facilitate the match.
      if v_viewer_profile_id = v_suggestion.profile_one_id
         or v_viewer_profile_id = v_suggestion.profile_two_id then
        if v_one_with_matchmaker and v_two_with_matchmaker then
          v_contact_id := case
            when v_viewer_profile_id = v_suggestion.profile_one_id then v_suggestion.profile_one_middle_person_id
            else v_suggestion.profile_two_middle_person_id
          end;
        elsif v_one_with_matchmaker then
          v_contact_id := v_suggestion.profile_one_middle_person_id;
        else
          v_contact_id := v_suggestion.profile_two_middle_person_id;
        end if;

        if v_contact_id is null then return; end if;

        return query
          select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
          from public.profiles p
          where p.id = v_contact_id;
        return;
      end if;

      -- The selected shadchan may see both participants, but the suggester
      -- cannot see their contact details unless they were actually selected.
      if (v_one_with_matchmaker and v_viewer_profile_id = v_suggestion.profile_one_middle_person_id)
         or (v_two_with_matchmaker and v_viewer_profile_id = v_suggestion.profile_two_middle_person_id) then
        return query
          select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
          from public.profiles p
          where p.id in (v_suggestion.profile_one_id, v_suggestion.profile_two_id)
          order by case when p.id = v_suggestion.profile_one_id then 0 else 1 end;
        return;
      end if;

      return;
    end if;

    -- Both participants chose to continue directly.
    if v_suggestion.profile_one_continuation_choice = 'by_themselves'
       and v_suggestion.profile_two_continuation_choice = 'by_themselves' then
      if v_viewer_profile_id = v_suggestion.profile_one_id then
        v_contact_id := v_suggestion.profile_two_id;
      elsif v_viewer_profile_id = v_suggestion.profile_two_id then
        v_contact_id := v_suggestion.profile_one_id;
      else
        return;
      end if;

      return query
        select p.id, p.first_name, p.last_name, p.phone, p.email, p.whatsapp, p.resume_url
        from public.profiles p
        where p.id = v_contact_id;
      return;
    end if;

    return;
  else
    raise exception 'Unsupported workflow type';
  end if;
end;
$$;

revoke all on function public.get_workflow_contact_profiles(text, uuid) from public, anon;
grant execute on function public.get_workflow_contact_profiles(text, uuid) to authenticated;

commit;
