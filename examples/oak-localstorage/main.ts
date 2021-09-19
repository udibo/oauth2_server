import {
  Application,
  BodyForm,
  challengeMethods,
  Cookies,
  generateCodeVerifier,
  Response,
  Router,
} from "./deps.ts";
import { AppUser } from "./models/user.ts";
import { oauth2, oauth2Router } from "./oauth2.ts";
import { Session } from "./models/session.ts";
import { sessionService, userService } from "./services/mod.ts";

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
    const token = await oauth2.getTokenForContext(context);
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
    const token = await oauth2.getTokenForContext(context);
    if (token?.user) {
      const redirectUri = request.url.searchParams.get("redirect_uri") ?? "/";
      response.redirect(redirectUri);
    } else {
      showLogin(response, cookies);
    }
  })
  .post("/login", async ({ request, response, cookies }) => {
    const sessionId: string | undefined = await cookies.get("sessionId");
    let session: Session | undefined = undefined;
    if (sessionId) {
      session = await sessionService.get(sessionId);
      await sessionService.delete(sessionId);
      cookies.delete("sessionId");
    }

    if (!session) {
      showLogin(
        response,
        cookies,
        new Error(`${sessionId ? "invalid" : "no"} session`),
      );
    } else if (request.hasBody) {
      try {
        const body: BodyForm = request.body({ type: "form" });
        const form: URLSearchParams = await body.value;
        const csrf = form.get("csrf");
        if (!csrf) throw new Error("csrf token required");
        if (csrf !== session.csrf) throw new Error("invalid csrf token");
        const username = form.get("username");
        if (!username) throw new Error("username required");
        const password = form.get("password");
        if (!password) throw new Error("password required");
        const user: AppUser | undefined = await userService.getAuthenticated(
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
        await sessionService.update(session);

        const authorizeUrl = new URL("http://localhost:8000/oauth2/authorize");
        const { searchParams } = authorizeUrl;
        searchParams.set("client_id", "1000");
        searchParams.set("response_type", "code");
        searchParams.set("state", session.state);
        searchParams.set(
          "code_challenge",
          challengeMethods.S256(session.codeVerifier),
        );
        searchParams.set("code_challenge_method", "S256");
        searchParams.set("redirect_uri", "http://localhost:8000/cb");
        response.redirect(authorizeUrl);
      } catch (error) {
        showLogin(response, cookies, error);
      }
    } else {
      showLogin(response, cookies, new Error("no request body"));
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
        const tokenUrl = new URL("http://localhost:8000/oauth2/token");
        const formParams = new URLSearchParams();
        formParams.set("client_id", "1000");
        formParams.set("grant_type", "authorization_code");
        formParams.set("code", code);
        formParams.set("redirect_uri", "http://localhost:8000/cb");
        formParams.set("code_verifier", codeVerifier);
        const now = Date.now();
        const headers = new Headers();
        headers.set("content-type", "application/x-www-form-urlencoded");
        const tokenResponse = await (await fetch(tokenUrl, {
          method: "POST",
          headers,
          body: formParams.toString(),
        })).json();
        const {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: expiresIn,
        } = tokenResponse;
        if (accessToken) session.accessToken = accessToken;
        if (refreshToken) session.refreshToken = refreshToken;
        if (expiresIn) session.accessTokenExpiresAt = now + expiresIn;
        delete session.user;
        delete session.state;
        delete session.codeVerifier;
        delete session.redirectUri;
        sessionService.update(session);
        response.redirect(redirectUri);
      } else {
        response.status = 400;
        response.body = "invalid request";
      }
    }
  })
  .get("/logout", async ({ response, cookies }) => {
    const sessionId: string | undefined = await cookies.get("sessionId");
    if (sessionId) {
      await sessionService.delete(sessionId);
      cookies.delete("sessionId");
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
