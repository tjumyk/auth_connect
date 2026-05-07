import { z } from "zod";

/**
 * Query params accepted by the callback route bound via `oauth.init_app(...)`.
 * Flask route: callback_path -> `_oauth_callback`
 */
export const OAuthCallbackQuerySchema = z.object({
  token: z.string().min(1),
  state: z.string().optional(),
  original_path: z.string().optional(),
});

/**
 * JSON error body returned by auth_connect for API clients
 * (for example, requires_login/requires_admin and redirect-needed responses).
 */
export const OAuthErrorResponseSchema = z.object({
  msg: z.string(),
  detail: z.unknown().optional(),
  redirect_url: z.string().optional(),
});

/**
 * Route params for admin user redirect route bound in `init_app`.
 * Flask route: client.admin_user_path
 */
export const AdminUserRouteParamsSchema = z.object({
  uid: z.coerce.number().int(),
});

/**
 * Route params for admin group redirect route bound in `init_app`.
 * Flask route: client.admin_group_path
 */
export const AdminGroupRouteParamsSchema = z.object({
  gid: z.coerce.number().int(),
});

/**
 * Route binding shape validated on backend (pydantic) and mirrored for frontend use.
 */
export const OAuthRouteBindingsSchema = z.object({
  callback_path: z.string().min(1),
  profile_path: z.string().min(1),
  admin_user_path: z.string().min(1),
  admin_group_path: z.string().min(1),
  profile_page: z.string().min(1),
  admin_user_page: z.string().min(1),
  admin_group_page: z.string().min(1),
});

/**
 * Helper to parse callback query params from URLSearchParams.
 */
export function parseOAuthCallbackQuery(params: URLSearchParams) {
  return OAuthCallbackQuerySchema.parse({
    token: params.get("token"),
    state: params.get("state") ?? undefined,
    original_path: params.get("original_path") ?? undefined,
  });
}

/**
 * Helper to parse backend error payload safely.
 */
export function parseOAuthErrorPayload(payload: unknown) {
  return OAuthErrorResponseSchema.parse(payload);
}

export type OAuthCallbackQuery = z.infer<typeof OAuthCallbackQuerySchema>;
export type OAuthErrorResponse = z.infer<typeof OAuthErrorResponseSchema>;
export type AdminUserRouteParams = z.infer<typeof AdminUserRouteParamsSchema>;
export type AdminGroupRouteParams = z.infer<typeof AdminGroupRouteParamsSchema>;
export type OAuthRouteBindings = z.infer<typeof OAuthRouteBindingsSchema>;
