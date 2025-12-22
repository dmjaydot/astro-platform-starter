import { supabase, getSession, hasAdminAccess } from './supabase';

export async function handleAdminLogin({ request, cookies, masterKey }) {
  const form = await request.formData();
  const loginType = form.get('loginType');

  if (loginType === 'master_key') {
    const submittedKey = form.get('masterKey');
    if (submittedKey === masterKey) {
      const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      cookies.set('admin-master-session', masterKey, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: expiry
      });
      return { redirect: '/admin' };
    }
    return { error: 'Invalid master key.' };
  }

  // Supabase login
  const email = form.get('email');
  const password = form.get('password');

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { error: error.message };

  if (data.session) {
    const { isAdmin, isModerator } = await hasAdminAccess(data.session.user.id);
    if (!isAdmin && !isModerator) {
      await supabase.auth.signOut();
      return { error: 'You do not have admin access.' };
    }

    cookies.set('sb-access-token', data.session.access_token, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7
    });
    cookies.set('sb-refresh-token', data.session.refresh_token, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7
    });

    return { redirect: '/admin' };
  }

  return { error: 'Unknown login error.' };
}
