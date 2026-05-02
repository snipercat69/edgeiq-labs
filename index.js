/**
 * EdgeIQ Autopilot Security — Main Worker
 * 
 * Turn your monitoring into action, not alerts.
 * 
 * Routes:
 *   POST /trigger          — Trigger a fix (SSL renew, header fix, GitHub issue)
 *   GET  /status/:fixId    — Check fix status
 *   GET  /customer/:customerId/config — Get customer config
 *   POST /customer/:customerId/config — Set customer config (API token, domain, etc.)
 *   GET  /fixes            — List available fix modules
 *   GET  /health           — Health check
 */

import { sslRenew } from './fixes/ssl-renew.js';
import { headerFix } from './fixes/header-fix.js';
import { githubIssue } from './fixes/github-issue.js';

// Available fix modules
const FIX_MODULES = {
  'ssl-renew': {
    name: 'SSL Auto-Renew',
    description: 'Automatically renew expiring SSL certificates via Cloudflare Origin CA',
    version: '1.0.0',
    triggers: ['cert-expiring', 'manual', 'scheduled'],
  },
  'header-fix': {
    name: 'Security Header Auto-Fix',
    description: 'Deploy recommended security headers to Cloudflare Workers',
    version: '1.0.0',
    triggers: ['missing-headers', 'manual', 'scheduled'],
  },
  'github-issue': {
    name: 'GitHub Issue Auto-Create',
    description: 'Automatically create GitHub issues for vulnerabilities found during scans',
    version: '1.0.0',
    triggers: ['vulnerability-found', 'manual'],
  },
};

// CORS headers
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-EdgeIQ-Customer-ID',
};

// Rate limiting state (in-memory for MVP; use KV in production)
const rateLimitMap = new Map();

/**
 * Simple in-memory rate limiter (10 fix requests per customer per hour)
 */
function checkRateLimit(customerId) {
  const key = `rate:${customerId}`;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  
  let record = rateLimitMap.get(key);
  
  if (!record || (now - record.timestamp) > windowMs) {
    record = { count: 0, timestamp: now };
  }
  
  record.count++;
  
  if (record.count > 10) {
    return false;
  }
  
  rateLimitMap.set(key, record);
  return true;
}

/**
 * Generate a unique fix ID
 */
function generateFixId() {
  return `fix_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Handle incoming requests
 */
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { headers: CORS_HEADERS });
  }

  // Add CORS to all responses
  const addCors = (response) => {
    const newHeaders = new Headers(response.headers);
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };

  try {
    // Route: Health check
    if (path === '/health' && method === 'GET') {
      return addCors(new Response(JSON.stringify({
        status: 'ok',
        service: 'edgeiq-autopilot',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime ? Math.floor(process.uptime()) : 'unknown',
      }), { headers: { 'Content-Type': 'application/json' } }));
    }

    // Route: List available fix modules
    if (path === '/fixes' && method === 'GET') {
      return addCors(new Response(JSON.stringify({
        fixes: FIX_MODULES,
        count: Object.keys(FIX_MODULES).length,
      }), { headers: { 'Content-Type': 'application/json' } }));
    }

    // Route: Trigger a fix
    if (path === '/trigger' && method === 'POST') {
      return addCors(await handleTrigger(request, env));
    }

    // Route: Check fix status
    if (path.startsWith('/status/') && method === 'GET') {
      const fixId = path.split('/status/')[1];
      return addCors(await handleStatus(fixId, env));
    }

    // Route: Get customer config
    if (path.startsWith('/customer/') && path.endsWith('/config') && method === 'GET') {
      const parts = path.split('/');
      const customerId = parts[2];
      return addCors(await handleGetCustomerConfig(customerId, env));
    }

    // Route: Set customer config
    if (path.startsWith('/customer/') && path.endsWith('/config') && method === 'POST') {
      const parts = path.split('/');
      const customerId = parts[2];
      return addCors(await handleSetCustomerConfig(customerId, request, env));
    }

    // 404
    return addCors(new Response(JSON.stringify({
      error: 'Not found',
      path,
      method,
    }), { status: 404, headers: { 'Content-Type': 'application/json' } }));

  } catch (error) {
    console.error('Worker error:', error);
    return addCors(new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message,
    }), { status: 500, headers: { 'Content-Type': 'application/json' } }));
  }
}

/**
 * Handle fix trigger requests
 */
async function handleTrigger(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { fixType, customerId, target, options } = body;

  // Validate fix type
  if (!fixType || !FIX_MODULES[fixType]) {
    return new Response(JSON.stringify({
      error: 'Invalid fix type',
      validTypes: Object.keys(FIX_MODULES),
    }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // Rate limit check
  const effectiveCustomerId = customerId || 'anonymous';
  if (!checkRateLimit(effectiveCustomerId)) {
    return new Response(JSON.stringify({
      error: 'Rate limit exceeded',
      message: 'Maximum 10 fix requests per hour per customer',
      retryAfter: 3600,
    }), { status: 429, headers: { 'Content-Type': 'application/json' } });
  }

  // Generate fix ID and initialize state
  const fixId = generateFixId();
  const startTime = Date.now();

  // Execute fix asynchronously
  const executeFix = async () => {
    try {
      let result;

      switch (fixType) {
        case 'ssl-renew':
          result = await sslRenew.execute(target, options, env);
          break;
        case 'header-fix':
          result = await headerFix.execute(target, options, env);
          break;
        case 'github-issue':
          result = await githubIssue.execute(target, options, env);
          break;
        default:
          result = { success: false, error: 'Unknown fix type' };
      }

      // Store result in KV
      const fixState = {
        id: fixId,
        type: fixType,
        customerId: effectiveCustomerId,
        status: result.success ? 'completed' : 'failed',
        result,
        startedAt: new Date(startTime).toISOString(),
        completedAt: new Date().toISOString(),
      };

      if (env.AUTOPILOT_STATE) {
        await env.AUTOPILOT_STATE.put(`fix:${fixId}`, JSON.stringify(fixState));
      }

      return fixState;
    } catch (error) {
      console.error(`Fix ${fixId} failed:`, error);
      
      const fixState = {
        id: fixId,
        type: fixType,
        customerId: effectiveCustomerId,
        status: 'failed',
        error: error.message,
        startedAt: new Date(startTime).toISOString(),
        completedAt: new Date().toISOString(),
      };

      if (env.AUTOPILOT_STATE) {
        await env.AUTOPILOT_STATE.put(`fix:${fixId}`, JSON.stringify(fixState));
      }

      return fixState;
    }
  };

  // Start async execution
  const fixPromise = executeFix();

  // Return immediate response with fix ID
  return new Response(JSON.stringify({
    fixId,
    type: fixType,
    status: 'processing',
    message: 'Fix has been queued and is processing',
    statusUrl: `/status/${fixId}`,
    customerId: effectiveCustomerId,
  }), {
    status: 202,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle status check requests
 */
async function handleStatus(fixId, env) {
  if (!env.AUTOPILOT_STATE) {
    return new Response(JSON.stringify({
      error: 'State store not configured',
    }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }

  const stateStr = await env.AUTOPILOT_STATE.get(`fix:${fixId}`);
  
  if (!stateStr) {
    return new Response(JSON.stringify({
      error: 'Fix not found',
      fixId,
    }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }

  const state = JSON.parse(stateStr);
  return new Response(JSON.stringify(state), {
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Handle get customer config
 */
async function handleGetCustomerConfig(customerId, env) {
  if (!env.CUSTOMER_CONFIG) {
    return new Response(JSON.stringify({
      error: 'Config store not configured',
    }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }

  const configStr = await env.CUSTOMER_CONFIG.get(`customer:${customerId}`);
  
  if (!configStr) {
    return new Response(JSON.stringify({
      error: 'Customer not found',
      customerId,
    }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  }

  const config = JSON.parse(configStr);
  
  // Mask sensitive fields
  if (config.cfApiToken) config.cfApiToken = '***REDACTED***';
  if (config.githubToken) config.githubToken = '***REDACTED***';
  if (config.stripeCustomerId) config.stripeCustomerId = '***REDACTED***';

  return new Response(JSON.stringify({
    customerId,
    config,
    domain: config.domain,
    activeFixes: config.activeFixes || [],
  }), { headers: { 'Content-Type': 'application/json' } });
}

/**
 * Handle set customer config
 */
async function handleSetCustomerConfig(customerId, request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { cfApiToken, cfZoneId, domain, githubToken, activeFixes } = body;

  // Basic validation
  if (!domain) {
    return new Response(JSON.stringify({
      error: 'Domain is required',
    }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  if (cfApiToken && !cfApiToken.startsWith('Bearer ')) {
    return new Response(JSON.stringify({
      error: 'Cloudflare API token must be a Bearer token',
    }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  if (githubToken && !githubToken.startsWith('ghp_')) {
    return new Response(JSON.stringify({
      error: 'GitHub token must be a personal access token (ghp_...)',
    }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  // Get existing config or create new
  let existingConfig = {};
  if (env.CUSTOMER_CONFIG) {
    const existingStr = await env.CUSTOMER_CONFIG.get(`customer:${customerId}`);
    if (existingStr) {
      existingConfig = JSON.parse(existingStr);
    }
  }

  // Merge configs
  const newConfig = {
    ...existingConfig,
    customerId,
    domain,
    cfApiToken: cfApiToken || existingConfig.cfApiToken,
    cfZoneId: cfZoneId || existingConfig.cfZoneId,
    githubToken: githubToken || existingConfig.githubToken,
    activeFixes: activeFixes || existingConfig.activeFixes || [],
    updatedAt: new Date().toISOString(),
  };

  // Store config
  if (env.CUSTOMER_CONFIG) {
    await env.CUSTOMER_CONFIG.put(`customer:${customerId}`, JSON.stringify(newConfig));
  }

  // Return config without sensitive fields
  const responseConfig = { ...newConfig };
  if (responseConfig.cfApiToken) responseConfig.cfApiToken = '***REDACTED***';
  if (responseConfig.githubToken) responseConfig.githubToken = '***REDACTED***';

  return new Response(JSON.stringify({
    customerId,
    config: responseConfig,
    message: 'Configuration saved successfully',
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

// Export the worker
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
};