// netlify/functions/tiktok-webhook.js
/**
 * TikTok Webhook Handler with Signature Verification
 * 
 * FIXED VERSION - Works with Netlify Functions
 * 
 * This handles TikTok webhooks and verifies signatures according to:
 * https://developers.tiktok.com/doc/webhooks-signature-verification
 */

const crypto = require('crypto');

/**
 * Verifies TikTok webhook signature
 */
function verifyTikTokSignature(signatureHeader, rawBody, clientSecret, toleranceSeconds = 300) {
  try {
    if (!signatureHeader) {
      return { valid: false, error: 'Missing signature header' };
    }

    // Step 1: Extract timestamp and signatures from header
    const elements = signatureHeader.split(',');
    let timestamp = null;
    const signatures = [];
    
    for (const element of elements) {
      const [prefix, value] = element.split('=');
      if (prefix === 't') {
        timestamp = value;
      } else if (prefix === 's') {
        signatures.push(value);
      }
    }
    
    if (!timestamp) {
      return { valid: false, error: 'Missing timestamp in signature header' };
    }
    
    if (signatures.length === 0) {
      return { valid: false, error: 'Missing signature in header' };
    }
    
    // Step 2: Generate expected signature
    const signedPayload = `${timestamp}.${rawBody}`;
    const expectedSignature = crypto
      .createHmac('sha256', clientSecret)
      .update(signedPayload)
      .digest('hex');
    
    // Step 3: Compare signatures (timing-safe)
    let signatureMatched = false;
    for (const signature of signatures) {
      // Use constant-time comparison
      if (signature.length === expectedSignature.length) {
        const sigBuffer = Buffer.from(signature, 'hex');
        const expectedBuffer = Buffer.from(expectedSignature, 'hex');
        
        if (sigBuffer.length === expectedBuffer.length && 
            crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
          signatureMatched = true;
          break;
        }
      }
    }
    
    if (!signatureMatched) {
      console.log('[TikTok] Signature mismatch');
      console.log('[TikTok] Expected:', expectedSignature);
      console.log('[TikTok] Received:', signatures);
      return { valid: false, error: 'Signature verification failed' };
    }
    
    // Check timestamp tolerance
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const webhookTimestamp = parseInt(timestamp, 10);
    const timeDifference = Math.abs(currentTimestamp - webhookTimestamp);
    
    if (timeDifference > toleranceSeconds) {
      return {
        valid: false,
        error: `Timestamp too old. Diff: ${timeDifference}s, Max: ${toleranceSeconds}s`
      };
    }
    
    return { valid: true, error: null };
    
  } catch (error) {
    console.error('[TikTok] Verification error:', error);
    return { valid: false, error: `Exception: ${error.message}` };
  }
}

/**
 * Main Netlify Function Handler
 */
exports.handler = async (event, context) => {
  // Log incoming request for debugging
  console.log('[TikTok Webhook] Received request');
  console.log('[TikTok Webhook] Method:', event.httpMethod);
  console.log('[TikTok Webhook] Headers:', JSON.stringify(event.headers, null, 2));
  
  // Only accept POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }
  
  try {
    // Get signature from headers (case-insensitive)
    const signatureHeader = event.headers['x-tiktok-signature'] || 
                           event.headers['X-TikTok-Signature'];
    
    if (!signatureHeader) {
      console.log('[TikTok] Missing x-tiktok-signature header');
      return {
        statusCode: 401,
        body: JSON.stringify({ 
          error: 'Missing x-tiktok-signature header',
          received_headers: Object.keys(event.headers)
        })
      };
    }
    
    // Get client secret from environment
    const clientSecret = process.env.TIKTOK_CLIENT_SECRET;
    
    if (!clientSecret) {
      console.error('[TikTok] TIKTOK_CLIENT_SECRET not configured in Netlify');
      return {
        statusCode: 500,
        body: JSON.stringify({ error: 'Server configuration error' })
      };
    }
    
    // Verify signature using raw body
    const rawBody = event.body;
    console.log('[TikTok] Body length:', rawBody ? rawBody.length : 0);
    console.log('[TikTok] Signature header:', signatureHeader);
    
    const verification = verifyTikTokSignature(
      signatureHeader,
      rawBody,
      clientSecret
    );
    
    if (!verification.valid) {
      console.warn('[TikTok] Signature verification failed:', verification.error);
      return {
        statusCode: 401,
        body: JSON.stringify({
          error: 'Invalid signature',
          details: verification.error
        })
      };
    }
    
    console.log('[TikTok] ✓ Signature verified successfully');
    
    // Parse webhook payload
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (e) {
      console.error('[TikTok] Failed to parse JSON body:', e);
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid JSON payload' })
      };
    }
    
    console.log('[TikTok] Webhook type:', payload.type);
    console.log('[TikTok] Payload:', JSON.stringify(payload, null, 2));
    
    // Handle different webhook types
    switch (payload.type) {
      case 'user.authorization.revoked':
        console.log('[TikTok] User revoked authorization:', payload.data?.user_id);
        // TODO: Update database - mark user as unauthorized
        break;
        
      case 'video.publish':
        console.log('[TikTok] Video published:', payload.data?.video_id);
        // TODO: Store video metadata, notify admins
        break;
        
      case 'user.data.requested':
        console.log('[TikTok] Data request for user:', payload.data?.user_id);
        // TODO: Generate user data export
        break;
        
      default:
        console.log('[TikTok] Unknown webhook type:', payload.type);
    }
    
    // Always return 200 to acknowledge receipt
    // TikTok will retry if we return an error
    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        received: true,
        timestamp: new Date().toISOString()
      })
    };
    
  } catch (error) {
    console.error('[TikTok] Handler error:', error);
    
    // Still return 200 to prevent TikTok from retrying
    return {
      statusCode: 200,
      body: JSON.stringify({
        success: false,
        error: 'Internal error (logged)'
      })
    };
  }
};
