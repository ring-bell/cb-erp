import type { VercelRequest, VercelResponse } from '@vercel/node';
import { z } from 'zod';
import { requireAuth, invalidateUserAccess } from '../_lib/auth';
import { requirePermission } from '../_lib/rbac';
import { parse, uuidSchema } from '../_lib/validation';
import { getAdminClient } from '../_lib/db';
import { writeAudit } from '../_lib/audit';
import { handleError, Errors } from '../_lib/error';
import { rateLimit } from '../_lib/rate-limit';

const updateSchema = z.object({
  // 邮箱/密码走 Supabase Auth（service_role），其余字段走 profiles
  email: z.string().email().optional(),
  name: z.string().min(1).max(100).optional(),
  password: z.string().min(6).max(72).optional(),
  is_active: z.boolean().optional(),
  role_ids: z.array(z.string().uuid()).optional(),
});

async function getProfileWithRoles(supabase: any, id: string) {
  const { data, error } = await supabase
    .from('profiles')
    .select('*, user_roles(role_id, roles(id, name))')
    .eq('id', id)
    .single();
  if (error) {
    if (error.code === 'PGRST116') throw Errors.notFound('用户不存在');
    throw error;
  }
  return data;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    rateLimit(((req.headers['x-forwarded-for'] as string) || 'unknown') + ':' + (req.url || ''));
    const ctx = await requireAuth(req);
    const id = parse(uuidSchema, req.query.id);
    const supabase = getAdminClient();

    if (req.method === 'PATCH') {
      requirePermission(ctx, 'user.manage');
      const body = parse(updateSchema, req.body || {});
      if (Object.keys(body).length === 0) throw Errors.badRequest('无更新字段');
      // 目标用户必须存在
      await getProfileWithRoles(supabase, id);

      // 1) Auth 层更新：邮箱 / 密码
      if (body.email !== undefined || body.password !== undefined) {
        const authPatch: Record<string, unknown> = {};
        if (body.email !== undefined) authPatch.email = body.email;
        if (body.password !== undefined) authPatch.password = body.password;
        const { error: authErr } = await supabase.auth.admin.updateUserById(id, authPatch);
        if (authErr) {
          if (authErr.status === 409 || /already.*exist/i.test(authErr.message || '')) {
            throw Errors.conflict('邮箱已被其他账号使用');
          }
          throw authErr;
        }
      }

      // 2) profiles 字段更新
      const profilePatch: Record<string, unknown> = {};
      if (body.name !== undefined) profilePatch.display_name = body.name;
      if (body.is_active !== undefined) profilePatch.is_active = body.is_active;
      if (Object.keys(profilePatch).length > 0) {
        const { error: profileErr } = await supabase.from('profiles').update(profilePatch).eq('id', id);
        if (profileErr) throw profileErr;
      }

      // 3) 角色更新：整表替换 user_roles
      if (body.role_ids !== undefined) {
        const { error: delErr } = await supabase.from('user_roles').delete().eq('user_id', id);
        if (delErr) throw delErr;
        if (body.role_ids.length > 0) {
          const rows = body.role_ids.map((role_id) => ({ user_id: id, role_id }));
          const { error: insErr } = await supabase.from('user_roles').insert(rows);
          if (insErr) throw insErr;
        }
        invalidateUserAccess(id);
      }

      const after = await getProfileWithRoles(supabase, id);
      await writeAudit(ctx, req, 'update', 'user', id, null, after);
      return res.status(200).json({ data: after });
    }

    if (req.method === 'DELETE') {
      requirePermission(ctx, 'user.manage');
      if (id === ctx.userId) throw Errors.badRequest('不能删除当前登录账号');
      const before = await getProfileWithRoles(supabase, id);
      const isSuperAdmin = (before.user_roles || []).some((ur: any) => ur.roles?.name === 'super_admin');
      if (isSuperAdmin) throw Errors.badRequest('超级管理员不可删除');
      const { error: authErr } = await supabase.auth.admin.deleteUser(id);
      if (authErr) throw authErr;
      invalidateUserAccess(id);
      await writeAudit(ctx, req, 'delete', 'user', id, before, null);
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } });
  } catch (e) {
    return handleError(res, e);
  }
}
