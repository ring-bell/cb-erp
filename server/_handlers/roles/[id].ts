import type { VercelRequest, VercelResponse } from '@vercel/node';
import { z } from 'zod';
import { requireAuth, invalidateUserAccess } from '../_lib/auth';
import { requirePermission } from '../_lib/rbac';
import { getAdminClient } from '../_lib/db';
import { handleError, Errors } from '../_lib/error';
import { rateLimit } from '../_lib/rate-limit';

const schema = z.object({
  name: z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9_-]+$/),
  description: z.string().trim().max(256).optional().default(''),
  permissions: z.array(z.string().min(1).max(100)).default([]),
});
const protectedRoles = new Set(['super_admin', 'admin', 'manager', 'operator']);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    rateLimit(((req.headers['x-forwarded-for'] as string) || 'unknown') + ':' + (req.url || ''));
    const ctx = await requireAuth(req);
    requirePermission(ctx, 'user.manage');
    const id = String(req.query.id || '');
    if (!z.string().uuid().safeParse(id).success) throw Errors.badRequest('角色 ID 无效');
    const supabase = getAdminClient();
    const { data: existing, error: findError } = await supabase.from('roles').select('id, name').eq('id', id).maybeSingle();
    if (findError) throw findError;
    if (!existing) throw Errors.notFound('角色不存在');

    if (req.method === 'PATCH') {
      const parsed = schema.safeParse(req.body || {});
      if (!parsed.success) throw Errors.badRequest('请求参数错误');
      if (protectedRoles.has(existing.name) && parsed.data.name !== existing.name) {
        throw Errors.badRequest('系统内置角色不能重命名');
      }
      const codes = [...new Set(parsed.data.permissions)];
      let permissionIds: string[] = [];
      if (codes.length) {
        const { data, error } = await supabase.from('permissions').select('id, code').in('code', codes);
        if (error) throw error;
        if ((data || []).length !== codes.length) throw Errors.badRequest('包含不存在的权限码');
        permissionIds = (data || []).map((item: any) => item.id);
      }
      const { error: updateError } = await supabase.from('roles').update({
        name: parsed.data.name, description: parsed.data.description,
      }).eq('id', id);
      if (updateError) throw updateError;
      const { error: deleteError } = await supabase.from('role_permissions').delete().eq('role_id', id);
      if (deleteError) throw deleteError;
      if (permissionIds.length) {
        const { error } = await supabase.from('role_permissions')
          .insert(permissionIds.map((permission_id) => ({ role_id: id, permission_id })));
        if (error) throw error;
      }
      invalidateUserAccess();
      return res.status(200).json({ data: { id, ...parsed.data } });
    }

    if (req.method === 'DELETE') {
      if (protectedRoles.has(existing.name)) throw Errors.badRequest('系统内置角色不能删除');
      const { error } = await supabase.from('roles').delete().eq('id', id);
      if (error) throw error;
      invalidateUserAccess();
      return res.status(204).end();
    }
    return res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } });
  } catch (e) {
    return handleError(res, e);
  }
}
