// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import { getSession, hasAdminAccess } from "./lib/supabase";

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
  const session = await getSession(context.cookies);

  if (!session) {
    return context.redirect('/admin/login');
  }

  // Get admin access status using helper
  const { isAdmin, isModerator, profile } = await hasAdminAccess(session.user.id);

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
