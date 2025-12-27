// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import { supabase, hasAdminAccess } from "./lib/supabase";

// Simple in-memory cache for settings to avoid DB calls on every request
let maintenanceMode: boolean | null = null;
let signupEnabled: boolean | null = null;
let settingsCacheTime: number = 0;
const SETTINGS_CACHE_TTL = 30000; // 30 seconds

async function getSecuritySettings() {
  const now = Date.now();
  
  // Return cached values if fresh
  if (maintenanceMode !== null && now - settingsCacheTime < SETTINGS_CACHE_TTL) {
    return { maintenanceMode, signupEnabled };
  }
  
  // Fetch from database
  try {
    const { data, error } = await supabase
      .from('site_settings')
      .select('value')
      .eq('key', 'security')
      .single();
    
    if (!error && data) {
      maintenanceMode = data.value?.maintenanceMode ?? false;
      signupEnabled = data.value?.enableSignup ?? true;
      settingsCacheTime = now;
    } else {
      // Default values if table doesn't exist or error
      maintenanceMode = false;
      signupEnabled = true;
    }
  } catch (e) {
    // Default values on error
    maintenanceMode = false;
    signupEnabled = true;
  }
  
  return { maintenanceMode, signupEnabled };
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { cookies, url, redirect, locals } = context;
  const path = url.pathname;

  // Skip middleware for static assets
  if (path.startsWith('/_') || path.includes('.')) {
    return next();
  }

  // Initialize locals
  locals.session = null;
  locals.profile = null;
  locals.isAdmin = false;
  locals.isModerator = false;
  locals.isMasterKeySession = false;

  // Check for master key session first
  const masterKeySession = cookies.get("master_key_session")?.value;
  const adminMasterKey = import.meta.env.ADMIN_MASTER_KEY;

  if (masterKeySession && adminMasterKey && masterKeySession === adminMasterKey) {
    locals.isMasterKeySession = true;
    locals.isAdmin = true;
    locals.isModerator = true;
    
    // Master key users bypass maintenance mode
    return next();
  }

  // Check for Supabase session
  const accessToken = cookies.get("sb-access-token")?.value;
  const refreshToken = cookies.get("sb-refresh-token")?.value;

  if (accessToken && refreshToken) {
    try {
      // Set the session
      const { data: sessionData, error: sessionError } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

      if (sessionError) {
        // Clear invalid cookies
        cookies.delete("sb-access-token", { path: "/" });
        cookies.delete("sb-refresh-token", { path: "/" });

        if (path.startsWith("/admin") || path.startsWith("/dashboard")) {
          return redirect("/admin/login?error=session_expired");
        }
      } else if (sessionData.session) {
        locals.session = sessionData.session;

        // Check if tokens were refreshed
        if (sessionData.session.access_token !== accessToken) {
          cookies.set("sb-access-token", sessionData.session.access_token, {
            path: "/",
            httpOnly: true,
            secure: import.meta.env.PROD,
            sameSite: "lax",
            maxAge: 60 * 60 * 24 * 7, // 1 week
          });
          cookies.set("sb-refresh-token", sessionData.session.refresh_token, {
            path: "/",
            httpOnly: true,
            secure: import.meta.env.PROD,
            sameSite: "lax",
            maxAge: 60 * 60 * 24 * 30, // 30 days
          });
        }

        // Fetch user profile
        const { data: profile } = await supabase
          .from("profiles")
          .select("*")
          .eq("id", sessionData.session.user.id)
          .single();

        if (profile) {
          locals.profile = profile;
          locals.isAdmin = profile.role === "admin";
          locals.isModerator = profile.role === "moderator" || profile.role === "admin";
        }
      }
    } catch (error) {
      console.error("Auth error:", error);
      if (path.startsWith("/admin") || path.startsWith("/dashboard")) {
        return redirect("/admin/login?error=auth_failed");
      }
    }
  }

  // Check security settings (maintenance mode, signup)
  const { maintenanceMode: isMaintenanceMode, signupEnabled: isSignupEnabled } = 
    await getSecuritySettings();

  // Maintenance mode check (skip for admin routes, maintenance page, and authenticated admins)
  if (isMaintenanceMode) {
    const isAdminRoute = path.startsWith('/admin');
    const isMaintenancePage = path === '/maintenance';
    const isAdmin = locals.isAdmin || locals.isMasterKeySession;
    
    // Allow admins and admin routes through
    if (!isAdminRoute && !isMaintenancePage && !isAdmin) {
      return redirect('/maintenance');
    }
  }

  // Signup disabled check
  if (!isSignupEnabled && path === '/signup') {
    return redirect('/?error=signup_disabled');
  }

  // Admin route protection
  if (path.startsWith("/admin")) {
    // Skip protection for login and setup pages
    if (path === "/admin/login" || path === "/admin/setup") {
      return next();
    }

    // Check for any valid auth (master key or session)
    if (!locals.isMasterKeySession && !locals.session) {
      return redirect("/admin/login");
    }

    // Check admin access using the helper function for non-master-key sessions
    if (!locals.isMasterKeySession) {
      const hasAccess = await hasAdminAccess(locals.session.user.id);
      if (!hasAccess && !locals.isAdmin && !locals.isModerator) {
        return redirect("/unauthorized");
      }
    }

    // For settings page, require admin role
    if (path === "/admin/settings" && !locals.isAdmin && !locals.isMasterKeySession) {
      return redirect("/unauthorized");
    }
  }

  // Dashboard route protection
  if (path.startsWith("/dashboard")) {
    if (!locals.session) {
      return redirect("/login?redirect=" + encodeURIComponent(path));
    }
  }

  return next();
});
