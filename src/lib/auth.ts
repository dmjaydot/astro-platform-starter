// src/lib/auth.ts
// Authentication helpers for Astro pages

import { supabase, getSession, isAdmin, isCreator } from './supabase';
import type { AstroCookies } from 'astro';

export interface User {
  id: string;
  email: string;
  name?: string;
}

export interface AuthSession {
  user: User;
  isAdmin: boolean;
  isCreator: boolean;
}

/**
 * Get current authenticated session from cookies
 */
export async function getAuthSession(cookies: AstroCookies): Promise<AuthSession | null> {
  const session = await getSession(cookies);

  if (!session) {
    return null;
  }

  const user = session.user;
  const [adminCheck, creatorCheck] = await Promise.all([
    isAdmin(user.id),
    isCreator(user.id),
  ]);

  return {
    user: {
      id: user.id,
      email: user.email || '',
      name: user.user_metadata?.name,
    },
    isAdmin: adminCheck,
    isCreator: creatorCheck,
  };
}

// Alias for backwards compatibility
export const getSessionFromCookies = getAuthSession;

/**
 * Require authentication - returns session or redirect path
 */
export async function requireAuth(
  cookies: AstroCookies, 
  redirectTo: string = '/creator/login'
): Promise<{ session: AuthSession } | { redirect: string }> {
  const session = await getAuthSession(cookies);
  
  if (!session) {
    return { redirect: redirectTo };
  }
  
  return { session };
}

/**
 * Require admin role - returns session or redirect path
 */
export async function requireAdmin(
  cookies: AstroCookies, 
  redirectTo: string = '/'
): Promise<{ session: AuthSession } | { redirect: string }> {
  const session = await getAuthSession(cookies);
  
  if (!session || !session.isAdmin) {
    return { redirect: redirectTo };
  }
  
  return { session };
}

/**
 * Require creator role - returns session or redirect path
 */
export async function requireCreator(
  cookies: AstroCookies, 
  redirectTo: string = '/creator/login'
): Promise<{ session: AuthSession } | { redirect: string }> {
  const session = await getAuthSession(cookies);
  
  if (!session || !session.isCreator) {
    return { redirect: redirectTo };
  }
  
  return { session };
}
