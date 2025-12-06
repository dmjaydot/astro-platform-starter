// src/lib/supabase.ts
// Supabase client for Astro on Netlify
// Uses environment variables from Netlify dashboard

import { createClient } from '@supabase/supabase-js';
import type { AstroCookies } from 'astro';

// Environment variables set in Netlify
const supabaseUrl = import.meta.env.SUPABASE_URL;
const supabaseAnonKey = import.meta.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = import.meta.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY');
}

// Public client (uses anon key, respects RLS)
export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Admin client (uses service key, bypasses RLS) - use carefully!
export const supabaseAdmin = supabaseServiceKey 
  ? createClient(supabaseUrl, supabaseServiceKey)
  : supabase;

// Get session from cookies
export async function getSession(cookies: AstroCookies) {
  const accessToken = cookies.get('sb-access-token')?.value;
  const refreshToken = cookies.get('sb-refresh-token')?.value;

  if (!accessToken || !refreshToken) {
    return null;
  }

  const { data, error } = await supabase.auth.setSession({
    access_token: accessToken,
    refresh_token: refreshToken,
  });

  if (error) {
    console.error('Session error:', error.message);
    return null;
  }

  return data.session;
}

// Set auth cookies
export function setAuthCookies(
  cookies: AstroCookies, 
  accessToken: string, 
  refreshToken: string
) {
  const cookieOptions = {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const,
    maxAge: 60 * 60 * 24 * 7, // 1 week
  };

  cookies.set('sb-access-token', accessToken, cookieOptions);
  cookies.set('sb-refresh-token', refreshToken, cookieOptions);
}

// Clear auth cookies
export function clearAuthCookies(cookies: AstroCookies) {
  cookies.delete('sb-access-token', { path: '/' });
  cookies.delete('sb-refresh-token', { path: '/' });
}

// Check if user is admin
export async function isAdmin(userId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('admins')
    .select('id')
    .eq('auth_id', userId)
    .single();

  return !error && !!data;
}

// Check if user is creator
export async function isCreator(userId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('creators')
    .select('id')
    .eq('id', userId)
    .single();

  return !error && !!data;
}

// Get creator profile
export async function getCreatorProfile(userId: string) {
  const { data, error } = await supabase
    .from('creators')
    .select('*')
    .eq('id', userId)
    .single();

  if (error) return null;
  return data;
}

// Get admin profile
export async function getAdminProfile(userId: string) {
  const { data, error } = await supabase
    .from('admins')
    .select('*')
    .eq('auth_id', userId)
    .single();

  if (error) return null;
  return data;
}
