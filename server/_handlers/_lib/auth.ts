import type { VercelRequest } from '@vercel/node';
import { getAdminClient } from './db';
import { Errors } from './error';

export interface AuthContext {
  userId: string;
  email: string;
  displayName: string;
  roles: string[];
  permissions: string[];
}

function extractToken(req: VercelRequest): string | null {
  const h = req.headers.authorization;
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

export interface UserAccess {
  roles: string[];
  permissions: string[];
}

// 实例级权限缓存：60 秒 TTL。
// Supabase 冷启动/连接初期偶发返回空数组（非报错），若每次都直查，
// 第一个冷启动请求仍可能拿到空结果；缓存命中后后续请求不再依赖数据库抖动。
const accessCache = new Map<string, { expireAt: number; roles: string[]; permissions: string[] }>();
const CACHE_TTL_MS = 60 * 1000;

export function invalidateUserAccess(userId?: string) {
  if (userId) accessCache.delete(userId);
  else accessCache.clear();
}

// 单次完整加载：user_roles -> roles -> role_permissions -> permissions。
// 查询失败必须显性报错，禁止静默当成"无角色"（否则会误报 403 无权限）。
async function loadUserAccessOnce(supabase: any, userId: string): Promise<UserAccess> {
  const roles: string[] = [];
  const permissionsSet = new Set<string>();

  const { data: userRoles, error: userRolesErr } = await supabase
    .from('user_roles')
    .select('role_id')
    .eq('user_id', userId);
  if (userRolesErr) throw new Error('加载用户角色失败: ' + userRolesErr.message);

  const roleIds = (userRoles || []).map((r: any) => r.role_id);
  if (roleIds.length) {
    const { data: roleData, error: roleErr } = await supabase
      .from('roles')
      .select('name')
      .in('id', roleIds);
    if (roleErr) throw new Error('加载角色定义失败: ' + roleErr.message);
    for (const r of roleData || []) if (r.name) roles.push(r.name);

    const { data: rpData, error: rpErr } = await supabase
      .from('role_permissions')
      .select('permission_id')
      .in('role_id', roleIds);
    if (rpErr) throw new Error('加载角色权限失败: ' + rpErr.message);
    const permIds = (rpData || []).map((r: any) => r.permission_id);
    if (permIds.length) {
      const { data: permData, error: permErr } = await supabase
        .from('permissions')
        .select('code')
        .in('id', permIds);
      if (permErr) throw new Error('加载权限定义失败: ' + permErr.message);
      for (const p of permData || []) if (p.code) permissionsSet.add(p.code);
    }
  }

  return { roles, permissions: Array.from(permissionsSet) };
}

// 加载用户角色与权限（带缓存 + 空结果抖动退避重试）。
// 只要最终拿到任意角色或权限即视为成功；整段查询（不止 user_roles）
// 在冷启动初期都可能偶发返回空数组，因此对完整加载结果做多次退避重试，
// 覆盖最长约 5s 抖动窗口，仍为空才判定"无角色"。
export async function loadUserAccess(supabase: any, userId: string): Promise<UserAccess> {
  const cached = accessCache.get(userId);
  if (cached && cached.expireAt > Date.now()) {
    return { roles: cached.roles, permissions: cached.permissions };
  }

  const retryDelays = [0, 500, 1500, 3000];
  let last: UserAccess = { roles: [], permissions: [] };
  for (const delay of retryDelays) {
    if (delay > 0) await new Promise((r) => setTimeout(r, delay));
    last = await loadUserAccessOnce(supabase, userId);
    if (last.roles.length > 0 || last.permissions.length > 0) break;
  }

  accessCache.set(userId, {
    expireAt: Date.now() + CACHE_TTL_MS,
    roles: last.roles,
    permissions: last.permissions,
  });
  return last;
}

// 验证 JWT（经 Supabase Auth），并加载用户角色与权限。
// 这是每个业务 API 的入口：Authentication -> Authorization。
export async function requireAuth(req: VercelRequest): Promise<AuthContext> {
  const token = extractToken(req);
  if (!token) throw Errors.unauthorized('未登录或缺少令牌');

  const supabase = getAdminClient();
  const { data: authData, error: authErr } = await supabase.auth.getUser(token);
  if (authErr || !authData.user) {
    throw Errors.unauthorized('登录已失效，请重新登录');
  }
  const userId = authData.user.id;

  // 加载 profile
  const { data: profile } = await supabase
    .from('profiles')
    .select('id, email, display_name, is_active')
    .eq('id', userId)
    .maybeSingle();
  if (profile && (profile as any).is_active === false) {
    // Treat a disabled account as an invalid session so the client clears the
    // authenticated UI instead of remaining logged in with repeated 403s.
    throw Errors.unauthorized('账号已停用，请联系管理员');
  }

  // 加载角色与权限（带缓存 + 空结果抖动退避重试，见 loadUserAccess）
  const { roles, permissions } = await loadUserAccess(supabase, userId);

  return {
    userId,
    email: authData.user.email || profile?.email || '',
    displayName: (profile as any)?.display_name || '',
    roles,
    permissions: Array.from(permissions),
  };
}
