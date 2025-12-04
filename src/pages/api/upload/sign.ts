// src/pages/api/upload/sign.ts
import type { APIRoute } from 'astro';
import crypto from 'crypto';

export const POST: APIRoute = async () => {
  const timestamp = Math.round(Date.now() / 1000);
  const apiSecret = import.meta.env.CLOUDINARY_API_SECRET;
  const cloudName = import.meta.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = import.meta.env.CLOUDINARY_API_KEY;
  const uploadPreset = import.meta.env.CLOUDINARY_UPLOAD_PRESET || 'banity_unsigned';

  if (!apiSecret) throw new Error('Missing Cloudinary secret');

  // Cloudinary expects signature of: timestamp + secret
  const signature = crypto
    .createHash('sha1')
    .update(`timestamp=${timestamp}${apiSecret}`)
    .digest('hex');

  return new Response(
    JSON.stringify({
      uploadUrl: `https://api.cloudinary.com/v1_1/${cloudName}/auto/upload`,
      timestamp,
      signature,
      api_key: apiKey,
      upload_preset: uploadPreset,
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );
};
