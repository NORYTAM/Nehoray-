import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const APP_URL = "https://app.zivugmishamayim.com/";
const FROM_ADDRESS = "Zivug Mishamayim <matches@zivugmishamayim.com>";
const MAX_TITLE_LENGTH = 120;
const MAX_BODY_LENGTH = 2000;

const MATCH_EMAIL_SUBJECTS: Record<string, string> = {
  match_accepted: "Both sides said yes",
  suggestion_both_accepted: "Both sides said yes",
  suggestion: "You have a match suggestion",
  suggestion_declined: "A match was declined",
  suggestion_rejected: "A match was declined",
  suggestion_other_side_yes: "A match suggestion is waiting",
  intro_request_from_matchmaker: "A match suggestion is waiting",
  intro_both_accepted: "Both sides said yes",
  intro_declined: "A match was declined",
  matchmaker_request: "You have a matchmaking request",
  matchmaker_responded: "A match was declined",
  matchmaker_selected: "You were asked to make a match",
  info_request: "Someone asked you for information",
};

type NotificationData = Record<string, unknown>;
type ProfileRow = {
  id: string;
  user_id: string;
  role: string | null;
  status: string | null;
  is_active: boolean | null;
  account_status: string | null;
  matchmaker_id?: string | null;
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function shouldSendMatchEmail(type: string, data: NotificationData): boolean {
  if (type === "matchmaker_selected") {
    return data.purpose == null || data.purpose === "facilitator_chosen";
  }
  if (type === "matchmaker_responded") {
    return data.response === "rejected";
  }
  return Object.prototype.hasOwnProperty.call(MATCH_EMAIL_SUBJECTS, type);
}

async function getProfileByUserId(
  adminClient: SupabaseClient,
  userId: string,
): Promise<ProfileRow | null> {
  const { data, error } = await adminClient
    .from("profiles")
    .select("id, user_id, role, status, is_active, account_status, matchmaker_id")
    .eq("user_id", userId)
    .maybeSingle();
  if (error || !data) return null;
  return data as ProfileRow;
}

async function getProfileById(
  adminClient: SupabaseClient,
  profileId: string,
): Promise<ProfileRow | null> {
  const { data, error } = await adminClient
    .from("profiles")
    .select("id, user_id, role, status, is_active, account_status, matchmaker_id")
    .eq("id", profileId)
    .maybeSingle();
  if (error || !data) return null;
  return data as ProfileRow;
}

async function isAdmin(adminClient: SupabaseClient, userId: string): Promise<boolean> {
  const { data, error } = await adminClient
    .from("admin_users")
    .select("user_id")
    .eq("user_id", userId)
    .maybeSingle();
  return !error && !!data;
}

async function authorizeNotification(
  adminClient: SupabaseClient,
  callerId: string,
  recipientUserId: string,
  data: NotificationData,
): Promise<boolean> {
  const type = stringValue(data.type);
  if (!type) return false;

  const [actor, recipient] = await Promise.all([
    getProfileByUserId(adminClient, callerId),
    getProfileByUserId(adminClient, recipientUserId),
  ]);
  const callerIsAdmin = await isAdmin(adminClient, callerId);

  const active = (profile: ProfileRow | null): profile is ProfileRow =>
    !!profile &&
    profile.status === "approved" &&
    profile.is_active === true &&
    (profile.account_status ?? "active") === "active";

  switch (type) {
    case "admin_new_profile":
    case "admin_profile_resubmitted": {
      const profileId = stringValue(data.profileId);
      if (!profileId || !actor || !(await isAdmin(adminClient, recipientUserId))) return false;
      const owner = await getProfileById(adminClient, profileId);
      return !!owner && owner.user_id === callerId && owner.status === "pending";
    }

    case "profile_approved":
    case "profile_update_approved":
    case "profile_rejected":
    case "profile_update_rejected": {
      if (!callerIsAdmin || !recipient) return false;
      const profileId = stringValue(data.profileId);
      if (!profileId) return false;
      const owner = await getProfileById(adminClient, profileId);
      if (!owner || owner.user_id !== recipientUserId) return false;
      return type.endsWith("_approved")
        ? owner.status === "approved"
        : owner.status === "rejected";
    }

    case "matchmaker_request": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !active(recipient)) return false;
      const { data: request } = await adminClient
        .from("intro_requests")
        .select("requester_id, requested_profile_id, requester_middle_person_id, status")
        .eq("id", requestId)
        .maybeSingle();
      return !!request &&
        request.requester_id === actor.id &&
        request.requester_middle_person_id === recipient.id &&
        request.status === "pending_matchmaker" &&
        (!data.requestedProfileId || data.requestedProfileId === request.requested_profile_id);
    }

    case "matchmaker_responded": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !recipient) return false;
      const { data: request } = await adminClient
        .from("intro_requests")
        .select("requester_id, requester_middle_person_id, matchmaker_status")
        .eq("id", requestId)
        .maybeSingle();
      const requester = request ? await getProfileById(adminClient, request.requester_id) : null;
      return !!request && !!requester &&
        request.requester_middle_person_id === actor.id &&
        requester.user_id === recipientUserId &&
        request.matchmaker_status === data.response;
    }

    case "intro_request_from_matchmaker": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !recipient) return false;
      const { data: request } = await adminClient
        .from("intro_requests")
        .select("requested_profile_id, requester_middle_person_id, status, matchmaker_status")
        .eq("id", requestId)
        .maybeSingle();
      return !!request &&
        request.requester_middle_person_id === actor.id &&
        request.requested_profile_id === recipient.id &&
        request.status === "pending_requested" &&
        request.matchmaker_status === "accepted";
    }

    case "intro_both_accepted":
    case "requested_responded":
    case "intro_declined":
    case "match_accepted": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !recipient) return false;
      const { data: request } = await adminClient
        .from("intro_requests")
        .select("requester_id, requested_profile_id, requester_middle_person_id, status, matchmaker_status, requested_status")
        .eq("id", requestId)
        .maybeSingle();
      if (!request) return false;
      const participants = [request.requester_id, request.requested_profile_id];
      const actorIsParticipant = participants.includes(actor.id);
      const recipientIsParticipant = participants.includes(recipient.id);
      if (type === "match_accepted") {
        return actorIsParticipant && recipientIsParticipant &&
          ["accepted", "completed"].includes(request.status);
      }
      if (type === "intro_both_accepted") {
        return actor.id === request.requested_profile_id &&
          recipient.id === request.requester_middle_person_id &&
          request.matchmaker_status === "accepted" &&
          request.requested_status === "accepted";
      }
      if (type === "requested_responded") {
        return actor.id === request.requested_profile_id &&
          recipient.id === request.requester_middle_person_id &&
          request.requested_status === data.response;
      }
      return actor.id === request.requested_profile_id &&
        recipient.id === request.requester_id &&
        request.status === "rejected" &&
        request.requested_status === "rejected";
    }

    case "matchmaker_selected": {
      if (!active(actor) || !recipient) return false;
      const purpose = data.purpose ?? "facilitator_chosen";
      const requestId = stringValue(data.requestId);
      const suggestionId = stringValue(data.suggestionId);

      if (requestId) {
        const { data: request } = await adminClient
          .from("intro_requests")
          .select("requester_id, requested_profile_id, requester_middle_person_id, requested_middle_person_id, status, requester_continuation_choice, requested_continuation_choice")
          .eq("id", requestId)
          .maybeSingle();
        if (!request || ![request.requester_id, request.requested_profile_id].includes(actor.id)) return false;
        if (purpose === "counterpart_notice") {
          const counterpartId = actor.id === request.requester_id
            ? request.requested_profile_id
            : request.requester_id;
          return recipient.id === counterpartId &&
            ["accepted", "completed"].includes(request.status);
        }
        const selectedId = request.requested_middle_person_id ?? request.requester_middle_person_id;
        return recipient.id === selectedId &&
          ["accepted", "completed"].includes(request.status);
      }

      if (suggestionId) {
        const { data: suggestion } = await adminClient
          .from("suggestions")
          .select("profile_one_id, profile_two_id, profile_one_middle_person_id, profile_two_middle_person_id, profile_one_status, profile_two_status, status")
          .eq("id", suggestionId)
          .maybeSingle();
        if (!suggestion || ![suggestion.profile_one_id, suggestion.profile_two_id].includes(actor.id)) return false;
        const otherId = actor.id === suggestion.profile_one_id
          ? suggestion.profile_two_id
          : suggestion.profile_one_id;
        if (purpose === "counterpart_notice") {
          return recipient.id === otherId &&
            ["accepted", "completed"].includes(suggestion.status);
        }
        const selectedId = actor.id === suggestion.profile_one_id
          ? suggestion.profile_one_middle_person_id
          : suggestion.profile_two_middle_person_id;
        return !!selectedId && recipient.id === selectedId &&
          ["accepted", "completed"].includes(suggestion.status);
      }

      const profileId = stringValue(data.profileId);
      const singleUserId = stringValue(data.singleUserId);
      return !!profileId && !!singleUserId &&
        callerId === singleUserId &&
        actor.id === profileId &&
        actor.role === "single" &&
        actor.matchmaker_id === recipient.id &&
        actor.is_active === true &&
        (actor.account_status ?? "active") === "active" &&
        ["pending", "approved"].includes(actor.status ?? "") &&
        active(recipient);
    }

    case "suggestion": {
      const suggestionId = stringValue(data.suggestionId);
      if (!suggestionId || !active(actor) || !recipient) return false;
      const { data: suggestion } = await adminClient
        .from("suggestions")
        .select("suggester_id, profile_one_id, profile_two_id, status")
        .eq("id", suggestionId)
        .maybeSingle();
      return !!suggestion &&
        suggestion.suggester_id === actor.id &&
        [suggestion.profile_one_id, suggestion.profile_two_id].includes(recipient.id) &&
        suggestion.status === "pending";
    }

    case "suggestion_both_accepted":
    case "suggestion_rejected":
    case "suggestion_declined":
    case "suggestion_reverted":
    case "suggestion_accepted_one_side":
    case "suggestion_other_side_yes": {
      const suggestionId = stringValue(data.suggestionId);
      if (!suggestionId || !active(actor) || !recipient) return false;
      const { data: suggestion } = await adminClient
        .from("suggestions")
        .select("suggester_id, profile_one_id, profile_two_id, profile_one_status, profile_two_status, status")
        .eq("id", suggestionId)
        .maybeSingle();
      if (!suggestion) return false;
      const participants = [suggestion.profile_one_id, suggestion.profile_two_id];
      const actorIsOne = actor.id === suggestion.profile_one_id;
      const actorIsTwo = actor.id === suggestion.profile_two_id;
      if (!actorIsOne && !actorIsTwo) return false;
      const actorStatus = actorIsOne ? suggestion.profile_one_status : suggestion.profile_two_status;
      const otherId = actorIsOne ? suggestion.profile_two_id : suggestion.profile_one_id;
      const recipientAllowed = recipient.id === suggestion.suggester_id || recipient.id === otherId ||
        (type === "suggestion_both_accepted" && participants.includes(recipient.id));
      if (!recipientAllowed) return false;

      if (type === "suggestion_both_accepted") {
        return suggestion.profile_one_status === "accepted" &&
          suggestion.profile_two_status === "accepted";
      }
      if (type === "suggestion_rejected" || type === "suggestion_declined") {
        return actorStatus === "rejected" && suggestion.status === "rejected";
      }
      if (type === "suggestion_reverted") {
        return actorStatus === "pending" && data.revertedBy === actor.id;
      }
      return actorStatus === "accepted" && suggestion.status !== "rejected";
    }

    case "info_request": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !recipient) return false;
      const { data: request } = await adminClient
        .from("info_requests")
        .select("requester_id, requested_profile_id, status")
        .eq("id", requestId)
        .maybeSingle();
      return !!request &&
        request.requester_id === actor.id &&
        request.requested_profile_id === recipient.id &&
        request.status === "pending";
    }

    case "info_request_approved":
    case "info_request_declined": {
      const requestId = stringValue(data.requestId);
      if (!requestId || !active(actor) || !recipient) return false;
      const { data: request } = await adminClient
        .from("info_requests")
        .select("requester_id, requested_profile_id, status")
        .eq("id", requestId)
        .maybeSingle();
      return !!request &&
        request.requested_profile_id === actor.id &&
        request.requester_id === recipient.id &&
        request.status === (type === "info_request_approved" ? "approved" : "rejected");
    }

    case "engagement_proposal":
    case "engagement_confirmed": {
      const engagementId = stringValue(data.engagementId);
      if (!engagementId || !active(actor) || !active(recipient)) return false;
      const { data: engagement } = await adminClient
        .from("engagements")
        .select("id, user1_id, user2_id, user1_confirmed, user2_confirmed, confirmed_at")
        .eq("id", engagementId)
        .maybeSingle();
      if (!engagement) return false;
      const actorIsOne = engagement.user1_id === callerId;
      const actorIsTwo = engagement.user2_id === callerId;
      if (!actorIsOne && !actorIsTwo) return false;
      const actorConfirmed = actorIsOne ? engagement.user1_confirmed : engagement.user2_confirmed;
      const recipientIsOne = engagement.user1_id === recipientUserId;
      const recipientIsTwo = engagement.user2_id === recipientUserId;
      if (!recipientIsOne && !recipientIsTwo) return false;
      const recipientConfirmed = recipientIsOne ? engagement.user1_confirmed : engagement.user2_confirmed;
      if (type === "engagement_proposal") {
        return actorConfirmed === true && recipientConfirmed === false;
      }
      return engagement.user1_confirmed === true &&
        engagement.user2_confirmed === true &&
        engagement.confirmed_at !== null;
    }

    case "engagement_news": {
      const engagementId = stringValue(data.engagementId);
      if (!engagementId || !active(actor) || !active(recipient)) return false;
      const { data: engagement } = await adminClient
        .from("engagements")
        .select("user1_id, user2_id, user1_confirmed, user2_confirmed, confirmed_at")
        .eq("id", engagementId)
        .maybeSingle();
      if (!engagement) return false;
      const actorIsParticipant = [engagement.user1_id, engagement.user2_id].includes(callerId);
      const recipientIsParticipant = [engagement.user1_id, engagement.user2_id].includes(recipientUserId);
      return actorIsParticipant && !recipientIsParticipant &&
        engagement.user1_confirmed === true &&
        engagement.user2_confirmed === true &&
        engagement.confirmed_at !== null;
    }

    default:
      return false;
  }
}

async function sendMatchEmail(
  adminClient: SupabaseClient,
  userId: string,
  title: string,
  body: string,
  subject: string,
): Promise<void> {
  const resendApiKey = Deno.env.get("RESEND_API_KEY");
  if (!resendApiKey) return;

  const { data: profile, error: profileError } = await adminClient
    .from("profiles")
    .select("notify_match_email, first_name")
    .eq("user_id", userId)
    .maybeSingle();
  if (profileError || profile?.notify_match_email === false) return;

  const { data: authData, error: authError } = await adminClient.auth.admin.getUserById(userId);
  if (authError || !authData?.user?.email) return;

  const firstName = profile.first_name?.trim() || "there";
  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5; color: #222; max-width: 560px; margin: 0 auto;">
      <p>Hi ${escapeHtml(firstName)},</p>
      <p><strong>${escapeHtml(title)}</strong></p>
      <p>${escapeHtml(body)}</p>
      <p style="margin: 28px 0;">
        <a href="${APP_URL}" style="background: #1293DA; color: #fff; text-decoration: none; padding: 12px 20px; border-radius: 8px; display: inline-block; font-weight: 600;">
          Open Zivug Mishamayim
        </a>
      </p>
      <p style="color: #888; font-size: 13px;">You can turn off these emails anytime in Settings.</p>
    </div>
  `;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: FROM_ADDRESS,
      to: [authData.user.email],
      subject,
      html,
    }),
  });
  if (!response.ok) {
    console.error("Resend match email failed:", response.status, (await response.text()).slice(0, 500));
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      console.error("Supabase environment is incomplete");
      return jsonResponse({ error: "Notification service is not configured" }, 503);
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user: caller }, error: authError } = await callerClient.auth.getUser();
    if (authError || !caller) return jsonResponse({ error: "Unauthorized" }, 401);

    let input: unknown;
    try {
      input = await req.json();
    } catch {
      return jsonResponse({ error: "Request body must be valid JSON" }, 400);
    }
    if (!input || typeof input !== "object") return jsonResponse({ error: "Invalid request body" }, 400);

    const payload = input as Record<string, unknown>;
    const userId = stringValue(payload.userId);
    const title = typeof payload.title === "string" ? payload.title.trim() : "";
    const body = typeof payload.body === "string" ? payload.body.trim() : "";
    const data = payload.data && typeof payload.data === "object" && !Array.isArray(payload.data)
      ? payload.data as NotificationData
      : null;

    if (!userId || !title || !body || !data || title.length > MAX_TITLE_LENGTH || body.length > MAX_BODY_LENGTH) {
      return jsonResponse({ error: "userId, title, body, and a supported notification type are required" }, 400);
    }
    if (JSON.stringify(data).length > 8000) return jsonResponse({ error: "Notification data is too large" }, 400);

    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const authorized = await authorizeNotification(adminClient, caller.id, userId, data);
    if (!authorized) {
      return jsonResponse({ error: "You are not authorized to send this notification" }, 403);
    }

    const notificationType = stringValue(data.type)!;
    const storedData: NotificationData = { ...data, actorUserId: caller.id };

    // Avoid duplicate sends caused by retries/double taps. The event is scoped to
    // the recipient and caller so independent participants can still receive it.
    const dedupe: NotificationData = {
      actorUserId: caller.id,
      type: notificationType,
    };
    for (const key of ["requestId", "suggestionId", "engagementId", "profileId", "purpose", "response"]) {
      const value = stringValue(data[key]);
      if (value) dedupe[key] = value;
    }
    const { count: duplicateCount, error: duplicateError } = await adminClient
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .contains("data", dedupe)
      .gte("created_at", new Date(Date.now() - 30_000).toISOString());
    if (duplicateError) {
      console.error("Unable to check duplicate notification:", duplicateError);
      return jsonResponse({ error: "Could not verify notification state" }, 500);
    }
    if ((duplicateCount ?? 0) > 0) {
      return jsonResponse({ success: true, duplicate: true });
    }

    const { error: notifError } = await adminClient.from("notifications").insert({
      user_id: userId,
      title,
      body,
      data: storedData,
      read: false,
    });
    if (notifError) {
      console.error("Error saving notification record:", notifError);
      return jsonResponse({ error: "Could not save notification" }, 500);
    }

    const { count: unreadCount, error: countError } = await adminClient
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("read", false);
    if (countError) console.error("Could not count unread notifications:", countError);

    if (shouldSendMatchEmail(notificationType, data)) {
      try {
        await sendMatchEmail(
          adminClient,
          userId,
          title,
          body,
          MATCH_EMAIL_SUBJECTS[notificationType] ?? title,
        );
      } catch (emailError) {
        console.error("Error sending match email:", emailError);
      }
    }

    const { data: tokens, error: tokensError } = await adminClient
      .from("push_tokens")
      .select("token")
      .eq("user_id", userId);
    if (tokensError) {
      console.error("Error fetching push tokens:", tokensError);
      return jsonResponse({ error: "Notification saved, but push tokens could not be loaded" }, 500);
    }

    if (!tokens || tokens.length === 0) {
      return jsonResponse({ success: true, message: "Notification saved, no push tokens found" });
    }

    const messages = tokens.map(({ token }) => ({
      to: token,
      sound: "default",
      title,
      body,
      data: storedData,
      badge: unreadCount ?? 1,
    }));
    const pushResponse = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(messages),
    });
    const result = await pushResponse.json();
    if (!pushResponse.ok) {
      console.error("Expo push notification error:", result);
      return jsonResponse({ error: "Notification saved, but push delivery failed" }, 502);
    }

    return jsonResponse({ success: true, result });
  } catch (error) {
    console.error("Error in send-notification:", error);
    return jsonResponse({ error: "Unexpected notification service error" }, 500);
  }
});
