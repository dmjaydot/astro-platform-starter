import { defineMiddleware } from "astro:middleware";
import { createClient } from "@supabase/supabase-js";

export const onRequest = defineMiddleware(async (context, next) => {
  const supabaseUrl = import.meta.env.PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;

  // Skip if Supabase is not configured
  if (!supabaseUrl || !supabaseAnonKey) {
    return next();
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey);

  // Get session from cookie
  const accessToken = context.cookies.get("sb-access-token")?.value;
  const refreshToken = context.cookies.get("sb-refresh-token")?.value;

  let session = null;

  if (accessToken && refreshToken) {
    const { data, error } = await supabase.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken,
    });
    if (!error) {
      session = data.session;
    }
  }

  const adminRoute = context.url.pathname.startsWith("/admin");

  if (adminRoute) {
    // Allow access to login page without session
    if (context.url.pathname === "/admin/login") {
      return next();
    }

    if (!session) {
      return context.redirect("/admin/login");
    }

    // Check if the user is in the admins table
    const { data: adminRecord } = await supabase
      .from("admins")
      .select("id")
      .eq("id", session.user.id)
      .maybeSingle();

    if (!adminRecord) {
      return context.redirect("/unauthorized");
    }
  }

  // Store supabase and session in locals for use in pages
  context.locals.supabase = supabase;
  context.locals.session = session;

  return next();
});
