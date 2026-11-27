import { createStaffAccess, type RecordsLike } from "../implementation/server/index.ts";

// Route handlers as a shop writes them: an admin sign-in, an admin-only list and a code lookup that staff may use too, from a
// browser with the cookie or from the shop's app with the bearer token.
export function staffRoutes(env: Record<string, string | undefined>, records: RecordsLike, now?: () => Date) {
  const access = createStaffAccess({ records, env, now, secure: true });
  const refuse = () => Response.json({ error: "UNAUTHORISED" }, { status: 401 });
  // The client's address as the host's own proxy wrote it, for the limit on wrong PINs: the last X-Forwarded-For entry, since a
  // client can write the first ones.
  const client = (request: Request) => request.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim() || "unknown";
  return {
    async signIn(request: Request): Promise<Response> {
      const body: unknown = await request.json().catch(() => null);
      const pin = body !== null && typeof body === "object" ? (body as { pin?: unknown }).pin : undefined;
      const result = await access.login("admin", pin, { client: client(request) });
      if (!result.ok) {
        const wait = result.code === "TOO_MANY_ATTEMPTS" ? { "retry-after": String(result.retryAfter) } : undefined;
        return Response.json({ error: result.code }, { status: result.status, headers: wait });
      }
      return Response.json({ token: result.token, expiresAt: result.expiresAt.toISOString() }, { headers: { "set-cookie": result.setCookie } });
    },
    async promotions(request: Request): Promise<Response> {
      if (!(await access.requestAllows(request, "admin"))) return refuse();
      return Response.json({ promotions: [] });
    },
    async lookup(request: Request): Promise<Response> {
      if (!(await access.requestAllows(request, "staff"))) return refuse();
      return Response.json({ code: new URL(request.url).searchParams.get("code") });
    },
    signOut(): Response {
      return new Response(null, { status: 204, headers: { "set-cookie": access.logout("admin") } });
    },
  };
}
