import { createClient, SupabaseClient } from '@supabase/supabase-js';

const url = process.env.SUPABASE_URL;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

let client: SupabaseClient | null = null;

// service_role 客户端：仅存在于服务端，绕过 RLS，用于业务逻辑读写。
// 前端永远拿不到 service_role key。
export function getAdminClient(): SupabaseClient {
  if (!url || !serviceKey) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  }
  if (!client) {
    client = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  }
  return client;
}

// Password login changes the client's in-memory auth session. Never perform it on
// the shared service-role client: doing so can make concurrent admin queries run
// with an end-user JWT (and consequently fail RLS checks or cross requests).
export function getLoginClient(): SupabaseClient {
  if (!url || !serviceKey) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  }
  return createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}
