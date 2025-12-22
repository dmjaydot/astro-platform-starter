// src/lib/auth.ts
import type { AstroCookies } from 'astro';
import { supabase } from './supabase';

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
  const { data: { session } } = await supabase.auth.getSession();

  if (!session?.user) return null;

  const user = session.user;

  // Replace these with your real role-check logic
  const adminCheck = await isAdmin(user.id);    // implement isAdmin
  const creatorCheck = await isCreator(user.id); // implement isCreator

  return {
    user: { id: user.id, email: user.email || '', name: user.user_metadata?.name },
    isAdmin: adminCheck,
    isCreator: creatorCheck,
  };
}

/**
 * Require authentication - throws if not authenticated
 */
export async function requireAuth(cookies: AstroCookies) {
  const session = await getAuthSession(cookies);
  if (!session) throw new Error('Unauthorized');
  return session;
}

/**
 * Require admin role
 */
export async function requireAdminRole(cookies: AstroCookies) {
  const session = await getAuthSession(cookies);
  if (!session || !session.isAdmin) throw new Error('Unauthorized');
  return session;
}

/**
 * Require creator role
 */
export async function requireCreatorRole(cookies: AstroCookies) {
  const session = await getAuthSession(cookies);
  if (!session || !session.isCreator) throw new Error('Unauthorized');
  return session;
}

// Optional alias for backwards compatibility
export const getSessionFromCookies = getAuthSession;
