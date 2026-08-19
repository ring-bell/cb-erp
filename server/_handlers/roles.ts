import type { VercelRequest, VercelResponse } from '@vercel/node';
import { requireAuth } from './_lib/auth';
import { requirePermission } from './_lib/rbac';
import { getAdminClient } from './_lib/db';
import { handleError, Errors } from './_lib/error';
import { rateLimit } from './_lib/rate-limit';
import { z } from 'zod';
import { invalidateUserAccess } from './_lib/auth';

const roleSchema = z.object({
  name: z.string().trim().min(1).max(64).regex(/^[a-zA-Z0-9_-]+$/, '角色名格式错误'),
  description: z.string().trim().max(256).optional().default(''),
  permissions: z.array(z.string().min(1).max(100)).default([]),
});

async function permissionIds(supabase: any, codes: string[]) {
  if (!codes.length) return [];
  const unique = [...new Set(codes)];
  const { data, error } = await supabase.from('permissions').select('id, code').in('code', unique);
  if (error) throw error;
  if ((data || []).length !== unique.length) throw Errors.badRequest('包含不存在的权限码');
  return (data || []).map((item: any) => item.id);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    rateLimit(((req.headers['x-forwarded-for'] as string) || 'unknown') + ':' + (req.url || ''));
    const ctx = await requireAuth(req);

    if (req.method === 'GET') {
      requirePermission(ctx, 'user.read');
      const supabase = getAdminClient();
      const { data, error } = await supabase
        .from('roles')
        .select('*, role_permissions(permission_id, permissions(code))')
        .order('name', { ascending: true });
      if (error) throw error;
      const normalized = (data || []).map((role: any) => ({
        ...role,
        permissions: (role.role_permissions || []).map((item: any) => item.permissions).filter(Boolean),
      }));
      return res.status(200).json({ data: normalized });
    }

    if (req.method === 'POST') {
      requirePermission(ctx, 'user.manage');
      const parsed = roleSchema.safeParse(req.body || {});
      if (!parsed.success) throw Errors.badRequest('请求参数错误');
      const supabase = getAdminClient();
      const ids = await permissionIds(supabase, parsed.data.permissions);
      const { data: role, error } = await supabase
        .from('roles').insert({ name: parsed.data.name, description: parsed.data.description }).select().single();
      if (error) throw error;
      if (ids.length) {
        const { error: mappingError } = await supabase.from('role_permissions')
          .insert(ids.map((permission_id: string) => ({ role_id: role.id, permission_id })));
        if (mappingError) {
          await supabase.from('roles').delete().eq('id', role.id);
          throw mappingError;
        }
      }
      invalidateUserAccess();
      return res.status(201).json({ data: role });
    }

    return res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } });
  } catch (e) {
    return handleError(res, e);
  }
}
