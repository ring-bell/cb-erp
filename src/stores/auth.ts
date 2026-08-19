import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { Session, User } from '@supabase/supabase-js'
import { supabase, supabaseStorageKey } from '@/services/supabase'
import { api } from '@/services/api'

export const useAuthStore = defineStore('auth', () => {
  const session = ref<Session | null>(null)
  const user = ref<User | null>(null)
  const roles = ref<string[]>([])
  const permissions = ref<string[]>([])
  async function init() {
    console.log('[auth:init] 开始, ts=' + new Date().toISOString())
    // 诊断：init 前 localStorage 中 session 键是否存在
    let rawSession = null
    try { rawSession = localStorage.getItem(supabaseStorageKey) } catch (e) { console.warn('[auth:init] 读取localStorage异常:', e) }
    console.log('[auth:init] localStorage键[' + supabaseStorageKey + ']:', rawSession ? '存在,长度=' + rawSession.length : '不存在')
    if (rawSession) {
      try {
        const parsed = JSON.parse(rawSession)
        console.log('[auth:init] 存储session概要: expires_at=' + parsed?.expires_at + ' now=' + Math.floor(Date.now()/1000) + ' 是否过期=' + (parsed?.expires_at ? (parsed.expires_at < Date.now()/1000 ? '是' : '否') : '未知(无expires_at)'))
      } catch (e) { console.warn('[auth:init] 解析存储session失败:', e) }
    }
    let { data } = await supabase.auth.getSession()
    console.log('[auth:init] getSession 结果:', data.session ? '有session' : 'session为空')
    if (!data.session) {
      console.log('[auth:init] 尝试 refreshSession...')
      const { data: refreshed, error: refreshErr } = await supabase.auth.refreshSession()
      if (refreshErr) {
        console.error('[auth:init] refreshSession 失败:', refreshErr?.message || refreshErr)
      } else {
        data = refreshed
        console.log('[auth:init] refreshSession 成功:', refreshed.session ? '有session' : '仍为空')
      }
    }
    session.value = data.session
    user.value = data.session?.user ?? null
    console.log('[auth:init] user 赋值结果:', user.value ? 'user有值(' + (user.value.email || 'no-email') + ')' : 'user为null')
    if (data.session) {
      await loadProfile()
    } else {
      console.warn('[auth:init] 无session，跳过 loadProfile')
    }
  }

  async function loadProfile() {
    if (!user.value) {
      console.warn('[auth:loadProfile] user为null，提前返回')
      return
    }
    try {
      // 确保 access_token 有效：getUser() 会校验当前会话 token，过期则自动刷新
      console.log('[auth:loadProfile] 开始, ts=' + new Date().toISOString())
      const { data: fresh } = await supabase.auth.getUser()
      console.log('[auth:loadProfile] getUser 结果:', fresh.user ? 'user有效' : 'user无效(将refreshSession)')
      if (!fresh.user) {
        const { error: refreshErr } = await supabase.auth.refreshSession()
        if (refreshErr) console.warn('[auth] refreshSession 失败:', refreshErr)
        else console.log('[auth:loadProfile] refreshSession 成功')
      }
      console.log('[auth:loadProfile] 请求 /auth/me ...')
      const { data } = await api.get('/auth/me')
      roles.value = data.roles ?? []
      permissions.value = data.permissions ?? []
      console.log('[auth:loadProfile] /auth/me 返回: roles=' + (data.roles ?? []).length + ' perms=' + (data.permissions ?? []).length)
      user.value = { ...user.value, email: data.user?.email, user_metadata: { ...(user.value?.user_metadata ?? {}), name: data.user?.name } }
    } catch (e: any) {
      console.error('[auth] loadProfile 失败:', e)
      try {
        const { ElMessage } = await import('element-plus')
        ElMessage.error('权限加载失败: ' + (e?.response?.data?.error?.message || e?.message || '未知错误，请重新登录'))
      } catch { /* ignore */ }
    }
  }

  async function signIn(email: string, password: string, captchaToken = '') {
    // 登录走服务端代理：Turnstile 人机验证、限流、失败锁定均在服务端执行
    const { data } = await api.post('/auth/login', { email, password, captchaToken })
    if (!data.session) throw new Error('登录失败：未返回会话')
    const { error: setErr } = await supabase.auth.setSession(data.session)
    if (setErr) throw setErr
    session.value = data.session
    user.value = data.session?.user ?? null
    roles.value = data.roles ?? []
    permissions.value = data.permissions ?? []
    if (user.value) {
      user.value = { ...user.value, email: data.user?.email, user_metadata: { ...user.value.user_metadata, name: data.user?.name } }
    }
  }

  async function signOut() {
    try {
      await supabase.auth.signOut()
    } catch {
      /* ignore */
    }
    session.value = null
    user.value = null
    roles.value = []
    permissions.value = []
    // 退出时清理本地业务日志，避免敏感信息残留在浏览器
    try {
      const { clearLogs } = await import('@/utils/log')
      clearLogs()
    } catch {
      /* ignore */
    }
  }

  function hasPermission(perm: string): boolean {
    return roles.value.includes('super_admin') || permissions.value.includes(perm)
  }

  return { session, user, roles, permissions, init, signIn, signOut, hasPermission }
})
