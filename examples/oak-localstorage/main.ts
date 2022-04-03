import {
  Application,
  BodyForm,
  challengeMethods,
  Cookies,
  generateCodeVerifier,
  Response,
  Router,
  Scope,
  Token,
  TokenBody,
} from "./deps.ts";
import { User } from "./models/user.ts";
import { oauth2, oauth2Router } from "./oauth2.ts";
import { Session } from "./models/session.ts";
import { sessionService, tokenService, userService } from "./services/mod.ts";
import { Client } from "./models/client.ts";

const loginPage = (csrf: string, error?: string | null) => `
  <html>
    <head>
      <title>Login</title>
    </head>
    <body>
      <form method="post">
        <label for="username">Username:</label><br/>
        <input type="text" id="username" name="username"/><br/>
        <label for="password">Password:</label><br/>
        <input type="password" id="password" name="password"/><br/>
        <input type="hidden" name="csrf" value="${csrf}"/>
        <input type="submit" value="Login"/>
      </form>
      ${error ? `<p style="background-color:red;">${error}</p>` : ""}
    </body>
  </html>
`;

const showLogin = async (
  response: Response,
  cookies: Cookies,
  error?: Error,
) => {
  const session = await sessionService.start();
  await cookies.set("sessionId", session.id, { httpOnly: true });
  if (error) response.status = 400;
  response.type = "html";
  response.body = loginPage(session.csrf, error?.message);
};

const router = new Router();
router
  .get("/", async (context) => {
    const { response } = context;
    const token = await oauth2.getTokenForContext(context)
      .catch(() => undefined);
    response.type = "html";
    response.body = `
      <html>
        <head>
          <title>Home</title>
        </head>
        <body>
          <h2>Home</h2>
          ${
      !token?.user
        ? '<a href="/login">Login</a>'
        : '<a href="/logout">Logout</a>'
    }
        </body>
      </html>
    `;
  })
  .get("/login", async (context) => {
    const { request, response, cookies } = context;
    const redirectUri = request.url.searchParams.get("redirect_uri") ?? "/";
    let token: Token<Client, User, Scope> | undefined = undefined;

    const refreshToken = await cookies.get("refreshToken");
    if (refreshToken) {
      const formParams = new URLSearchParams();
      formParams.set("client_id", "1000");
      formParams.set("grant_type", "refresh_token");
      formParams.set("refresh_token", refreshToken);
      const now = Date.now();
      const headers = new Headers();
      headers.set("content-type", "application/x-www-form-urlencoded");
      headers.set("authorization", `basic ${btoa("1000:1234")}`);
      const tokenResponse = await fetch("http://localhost:8000/oauth2/token", {
        method: "POST",
        headers,
        body: formParams.toString(),
      });
      const body = await tokenResponse.json();
      if (tokenResponse.status === 200) {
        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn,
        } = body as TokenBody;
        if (accessToken) {
          cookies.set("accessToken", accessToken, {
            httpOnly: true,
            expires: expiresIn ? new Date(now + (expiresIn * 1000)) : undefined,
          });
        }
        if (refreshToken) {
          cookies.set("refreshToken", refreshToken, {
            httpOnly: true,
            path: "/login",
          });
          cookies.set("refreshToken", refreshToken, {
            httpOnly: true,
            path: "/logout",
          });
          cookies.set("refreshToken", refreshToken, {
            httpOnly: true,
            path: "/oauth2/token",
          });
        }
        token = await oauth2.getToken(accessToken)
          .catch(() => undefined);
      } else {
        return showLogin(response, cookies);
      }
    }

    if (!token) {
      token = await oauth2.getTokenForContext(context)
        .catch(() => undefined);
    }

    if (token) {
      return response.redirect(redirectUri);
    } else {
      return showLogin(response, cookies);
    }
  })
  .post("/login", async ({ request, response, cookies }) => {
    const sessionId: string | undefined = await cookies.get("sessionId");
    let session: Session | undefined = sessionId
      ? await sessionService.get(sessionId)
      : undefined;

    if (!session) {
      return showLogin(
        response,
        cookies,
        new Error(`${sessionId ? "invalid" : "no"} session`),
      );
    }

    try {
      await sessionService.delete(sessionId!);
      cookies.delete("sessionId");
      const body: BodyForm = request.body({ type: "form" });
      const form: URLSearchParams = await body.value;
      const csrf = form.get("csrf");
      if (!csrf) throw new Error("csrf token required");
      if (csrf !== session.csrf) throw new Error("invalid csrf token");
      const username = form.get("username");
      if (!username) throw new Error("username required");
      const password = form.get("password");
      if (!password) throw new Error("password required");
      const user: User | undefined = await userService.getAuthenticated(
        username,
        password,
      );
      if (!user) throw new Error("incorrect username or password");
      const redirectUri = request.url.searchParams.get("redirect_uri") ?? "/";

      session = await sessionService.start();
      await cookies.set("sessionId", session.id, { httpOnly: true });
      session.user = user;
      session.state = crypto.randomUUID();
      session.redirectUri = redirectUri;
      session.codeVerifier = generateCodeVerifier();
      await sessionService.patch(session);

      const authorizeUrl = new URL("http://localhost:8000/oauth2/authorize");
      const { searchParams } = authorizeUrl;
      searchParams.set("client_id", "1000");
      searchParams.set("response_type", "code");
      searchParams.set("state", session.state);
      searchParams.set(
        "code_challenge",
        await challengeMethods.S256(session.codeVerifier),
      );
      searchParams.set("code_challenge_method", "S256");
      searchParams.set("redirect_uri", "http://localhost:8000/cb");
      response.redirect(authorizeUrl);
    } catch (error) {
      return showLogin(response, cookies, error);
    }
  })
  .get("/cb", async ({ request, response, cookies }) => {
    const sessionId: string | undefined = await cookies.get("sessionId");
    const session: Session | undefined = sessionId
      ? await sessionService.get(sessionId)
      : undefined;
    const authorizeParams = request.url.searchParams;
    if (authorizeParams.has("error")) {
      response.status = 400;
      response.body = authorizeParams.get("error");
    } else if (session) {
      const code = authorizeParams.get("code");
      const state = authorizeParams.get("state");
      const { state: expectedState, codeVerifier, redirectUri } = session;
      if (
        code && state && state === expectedState && codeVerifier && redirectUri
      ) {
        const formParams = new URLSearchParams();
        formParams.set("client_id", "1000");
        formParams.set("grant_type", "authorization_code");
        formParams.set("code", code);
        formParams.set("redirect_uri", "http://localhost:8000/cb");
        formParams.set("code_verifier", codeVerifier);
        const now = Date.now();
        const headers = new Headers();
        headers.set("content-type", "application/x-www-form-urlencoded");
        const tokenResponse = await fetch(
          "http://localhost:8000/oauth2/token",
          {
            method: "POST",
            headers,
            body: formParams.toString(),
          },
        );
        const body = await tokenResponse.json();
        if (tokenResponse.status === 200) {
          const {
            access_token: accessToken,
            refresh_token: refreshToken,
            expires_in: expiresIn,
          } = body as TokenBody;
          if (accessToken) {
            cookies.set("accessToken", accessToken, {
              httpOnly: true,
              expires: expiresIn
                ? new Date(now + (expiresIn * 1000))
                : undefined,
            });
          }
          if (refreshToken) {
            cookies.set("refreshToken", refreshToken, {
              httpOnly: true,
              path: "/login",
            });
            cookies.set("refreshToken", refreshToken, {
              httpOnly: true,
              path: "/logout",
            });
            cookies.set("refreshToken", refreshToken, {
              httpOnly: true,
              path: "/oauth2/token",
            });
          }
          session.user = null;
          session.state = null;
          session.codeVerifier = null;
          session.redirectUri = null;
          await sessionService.patch(session);
          response.redirect(redirectUri);
        } else {
          response.status = tokenResponse.status;
          response.body = body.error;
        }
      } else {
        response.status = 400;
        response.body = "invalid request";
      }
    }
  })
  .get("/logout", async ({ response, cookies }) => {
    const sessionId = await cookies.get("sessionId");
    if (sessionId) {
      await sessionService.delete(sessionId);
      cookies.delete("sessionId");
    }
    const accessToken = await cookies.get("accessToken");
    if (accessToken) {
      await tokenService.revoke(accessToken, "access_token");
      cookies.delete("accessToken");
    }
    const refreshToken = await cookies.get("refreshToken");
    if (refreshToken) {
      await tokenService.revoke(refreshToken, "refresh_token");
      cookies.delete("refreshToken", { path: "/login" });
      cookies.delete("refreshToken", { path: "/logout" });
      cookies.delete("refreshToken", { path: "/oauth2/token" });
    }
    response.redirect("/");
  })
  .get("/public", ({ response }) => {
    response.body = { success: true };
  })
  .get("/private", oauth2.authenticate(), ({ response }) => {
    response.body = { success: true };
  })
  .get("/admin", oauth2.authenticate("admin"), ({ response }) => {
    response.body = { success: true };
  })
  .use("/oauth2", oauth2Router.routes());

const app = new Application();
app.use(router.routes());
app.use(router.allowedMethods());

const port = 8000;
console.log(`Listening on port ${port}`);
await app.listen({ port });
