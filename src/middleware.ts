// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import { createClient } from "@supabase/supabase-js";

export const onRequest = defineMiddleware(async (context, next) => {
  const supabaseUrl = import.meta.env.PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;
  const masterKey = import.meta.env.ADMIN_MASTER_KEY;

  const pathname = context.url.pathname;
  
  // Public routes - no auth required
  const publicRoutes = [
    '/admin/login',
    '/admin/setup',
    '/api/auth',
    '/clips',
    '/',
  ];
  
  const isPublicRoute = publicRoutes.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  );
  
  // Skip middleware for public routes and non-admin pages
  if (isPublicRoute || !pathname.startsWith('/admin')) {
    return next();
  }

  // Check for master key session first (bypasses all other auth)
  const masterSession = context.cookies.get('admin-master-session')?.value;
  
  if (masterKey && masterSession === masterKey) {
    // Master key session is valid - grant full admin access
    context.locals.isMasterKeySession = true;
    context.locals.session = null;
    return next();
  }

  // Check for regular Supabase session
  if (!supabaseUrl || !supabaseAnonKey) {
    return context.redirect('/admin/login');
  }

  const supabase = createClient(supabaseUrl, supabaseAnonKey);

  // Get session from cookies
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
      
      // Update cookies if tokens were refreshed
      if (data.session && data.session.access_token !== accessToken) {
        context.cookies.set('sb-access-token', data.session.access_token, {
          path: '/',
          httpOnly: true,
          secure: import.meta.env.PROD,
          sameSite: 'lax',
          maxAge: 60 * 60 * 24 * 7
        });
        context.cookies.set('sb-refresh-token', data.session.refresh_token, {
          path: '/',
          httpOnly: true,
          secure: import.meta.env.PROD,
          sameSite: 'lax',
          maxAge: 60 * 60 * 24 * 7
        });
      }
    }
  }

  // No session - redirect to login
  if (!session) {
    return context.redirect('/admin/login');
  }

  // Check if user is in admins table
  const { data: adminRecord } = await supabase
    .from("admins")
    .select("id")
    .eq("id", session.user.id)
    .maybeSingle();

  // Also check profile role
  const { data: profile } = await supabase
    .from("profiles")
    .select("role")
    .eq("id", session.user.id)
    .single();

  const isAdmin = !!adminRecord || profile?.role === "admin";
  const isModerator = profile?.role === "moderator";

  // Admin-only routes
  const adminOnlyRoutes = ['/admin/users', '/admin/settings', '/admin/messages'];
  const isAdminOnlyRoute = adminOnlyRoutes.some(route => pathname.startsWith(route));

  // Moderator-accessible routes
  const modRoutes = ['/admin/review'];
  const isModRoute = modRoutes.some(route => pathname.startsWith(route));

  if (isAdminOnlyRoute && !isAdmin) {
    return context.redirect('/unauthorized');
  }

  if (isModRoute && !isAdmin && !isModerator) {
    return context.redirect('/unauthorized');
  }

  // For general admin routes, require admin or moderator
  if (!isAdmin && !isModerator) {
    return context.redirect('/unauthorized');
  }

  // Store session info in locals
  context.locals.session = session;
  context.locals.supabase = supabase;
  context.locals.isAdmin = isAdmin;
  context.locals.isModerator = isModerator;
  context.locals.isMasterKeySession = false;

  return next();
});
