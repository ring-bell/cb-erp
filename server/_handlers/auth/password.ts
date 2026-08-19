import type { VercelRequest, VercelResponse } from '@vercel/node';
import { requireAuth } from '../_lib/auth';
import { getAdminClient, getLoginClient } from '../_lib/db';
import { Errors, handleError } from '../_lib/error';
import { rateLimit } from '../_lib/rate-limit';

// POST /auth/password — 修改当前登录用户密码
// 鉴权：requireAuth（Bearer token）；校验旧密码使用隔离的登录 client；
// 更新密码：supabase auth admin.updateUserById（service_role 权限）。
export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    rateLimit(((req.headers['x-forwarded-for'] as string) || 'unknown') + ':' + (req.url || ''));
    const ctx = await requireAuth(req);

    if (req.method !== 'POST') {
      return res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' } });
    }

    const body = (req.body ?? {}) as { oldPassword?: string; newPassword?: string };
    const oldPassword = typeof body.oldPassword === 'string' ? body.oldPassword : '';
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

    if (!oldPassword) throw Errors.badRequest('请输入原密码');
    if (!newPassword) throw Errors.badRequest('请输入新密码');
    if (newPassword.length < 6) throw Errors.badRequest('新密码长度不能少于 6 位');

    // 1) 校验旧密码：用当前用户邮箱 + 原密码做一次登录验证
    const { error: signErr } = await getLoginClient().auth.signInWithPassword({
      email: ctx.email,
      password: oldPassword,
    });
    if (signErr) {
      throw Errors.badRequest('原密码不正确');
    }

    // 2) 更新密码（auth 管理员接口，service_role 可用）
    const supabase = getAdminClient();
    const { error: updateErr } = await supabase.auth.admin.updateUserById(ctx.userId, {
      password: newPassword,
    });
    if (updateErr) {
      console.error('[auth/password] updateUserById error:', updateErr.message || updateErr);
      throw Errors.badRequest('密码修改失败，请稍后重试');
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    return handleError(res, e);
  }
}
