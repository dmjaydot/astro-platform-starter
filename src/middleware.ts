// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import { supabase, getSession, hasAdminAccess } from "./lib/supabase";

export const onRequest = defineMiddleware(async (context, next) => {
  const masterKey = import.meta.env.ADMIN_MASTER_KEY;
  const pathname = context.url.pathname;
  
  // Public routes - no auth required
  const publicRoutes = [
    '/admin/login',
    '/admin/setup',
    '/api/auth',
    '/clips',
    '/',
    '/unauthorized',
    '/404',
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
    context.locals.isMasterKeySession = true;
    context.locals.session = null;
    context.locals.profile = null;
    context.locals.isAdmin = true;
    context.locals.isModerator = false;
    return next();
  }

  // Normal authentication
  const accessToken = context.cookies.get('sb-access-token')?.value;
  const refreshToken = context.cookies.get('sb-refresh-token')?.value;

  if (!accessToken || !refreshToken) {
    return context.redirect('/admin/login');
  }

  // Try to get/refresh session
  let session = null;
  
  try {
    const { data, error } = await supabase.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken,
    });

    if (error) {
      console.error('Session error:', error.message);
      
      // Clear invalid cookies
      context.cookies.delete('sb-access-token', { path: '/' });
      context.cookies.delete('sb-refresh-token', { path: '/' });
      
      return context.redirect('/admin/login?error=session_expired');
    }

    session = data.session;

    // If tokens were refreshed, update cookies
    if (session && (session.access_token !== accessToken || session.refresh_token !== refreshToken)) {
      context.cookies.set('sb-access-token', session.access_token, {
        path: '/',
        httpOnly: true,
        secure: import.meta.env.PROD,
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 7, // 7 days
      });
      context.cookies.set('sb-refresh-token', session.refresh_token, {
        path: '/',
        httpOnly: true,
        secure: import.meta.env.PROD,
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 7,
      });
    }
  } catch (err) {
    console.error('Auth error:', err);
    return context.redirect('/admin/login?error=auth_failed');
  }

  if (!session) {
    return context.redirect('/admin/login');
  }

  // Get admin access status using helper
  let isAdmin = false;
  let isModerator = false;
  let profile = null;

  try {
    const accessResult = await hasAdminAccess(session.user.id);
    isAdmin = accessResult.isAdmin;
    isModerator = accessResult.isModerator;
    profile = accessResult.profile;
  } catch (err) {
    console.error('Failed to check admin access:', err);
    return context.redirect('/admin/login?error=access_check_failed');
  }

  // Route-based access control
  const adminOnlyRoutes = ['/admin/users', '/admin/settings', '/admin/messages'];
  const isAdminOnlyRoute = adminOnlyRoutes.some(route => pathname.startsWith(route));

  const modRoutes = ['/admin/review', '/admin/campaigns', '/admin/communities'];
  const isModRoute = modRoutes.some(route => pathname.startsWith(route));

  if (isAdminOnlyRoute && !isAdmin) {
    return context.redirect('/unauthorized');
  }

  if (isModRoute && !isAdmin && !isModerator) {
    return context.redirect('/unauthorized');
  }

  if (!isAdmin && !isModerator) {
    return context.redirect('/unauthorized');
  }

  // Store in locals for page access
  context.locals.session = session;
  context.locals.profile = profile;
  context.locals.isAdmin = isAdmin;
  context.locals.isModerator = isModerator;
  context.locals.isMasterKeySession = false;

  return next();
});
