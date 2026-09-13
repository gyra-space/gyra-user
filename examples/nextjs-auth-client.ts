/**
 * Gyra 前端接入示例（Next.js / TS）。
 *
 * gyra-user 的响应格式与 Gyra 现有 `src/services/auth.ts` 完全一致，
 * 所以最小改动是「什么都不改」。要拿 refresh token 能力的话，
 * 把下面这个 axios 拦截器接进 `@/client/api` 即可。
 */

const API_BASE = '/api/v1';

const ACCESS_KEY = 'gyra_access_token';
const REFRESH_KEY = 'gyra_refresh_token';

export interface MeResponse {
  user: {
    id: number;
    name: string;
    fullname: string;
    email: string;
    avatar: string;
    oauth_provider: string;
    oauth_id: string;
    role: string;
    is_active: number;
  };
  user_channel: string;
  user_no: string;
  nick_name: string;
  avatar_url: string;
  email: string;
  role: string;
}

export const tokenStore = {
  get access() {
    return typeof window === 'undefined' ? null : localStorage.getItem(ACCESS_KEY);
  },
  get refresh() {
    return typeof window === 'undefined' ? null : localStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

/**
 * 挂到 axios 实例上：401 时自动用 refresh token 换一对新 token 并重试一次。
 * 轮换失败（被吊销 / 重放）就清空本地态并跳登录页。
 */
export function attachAuthInterceptor(axiosInstance: any) {
  axiosInstance.interceptors.request.use((config: any) => {
    const token = tokenStore.access;
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
  });

  axiosInstance.interceptors.response.use(
    (response: any) => response,
    async (error: any) => {
      const original = error.config;
      if (error.response?.status !== 401 || original?._retry) {
        return Promise.reject(error);
      }
      if (!tokenStore.refresh) {
        return Promise.reject(error);
      }
      original._retry = true;
      try {
        const { data } = await axiosInstance.post(`${API_BASE}/auth/refresh`, {
          refresh_token: tokenStore.refresh,
        });
        tokenStore.set(data.access_token, data.refresh_token);
        original.headers.Authorization = `Bearer ${data.access_token}`;
        return axiosInstance(original);
      } catch (refreshError) {
        tokenStore.clear();
        window.location.href = '/login?error=session_expired';
        return Promise.reject(refreshError);
      }
    },
  );
}

/** 第三方登录入口：直接跳后端，state / PKCE 由后端负责。 */
export function oauthLoginUrl(provider: string): string {
  return `${API_BASE}/auth/oauth/login?provider=${encodeURIComponent(provider)}`;
}

/**
 * 微信扫码（内嵌，不跳整页）：
 *   <iframe src={`${API_BASE}/auth/oauth/qr/wechat`} width="300" height="400" />
 * 扫码完成后 iframe 内页面会把顶层窗口导航到回调地址，无需前端轮询。
 */
export function wechatQrUrl(): string {
  return `${API_BASE}/auth/oauth/qr/wechat`;
}

/** 回调页：`/auth/callback/#token=...` 里取 token。 */
export function captureTokenFromFragment(): string | null {
  const hash = window.location.hash.replace(/^#/, '');
  const token = new URLSearchParams(hash).get('token');
  if (token) localStorage.setItem(ACCESS_KEY, token);
  return token;
}
