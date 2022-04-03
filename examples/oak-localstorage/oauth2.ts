import {
  AuthorizationCodeGrant,
  AuthorizationServer,
  AuthorizeParameters,
  ClientCredentialsGrant,
  loginRedirectFactory,
  OakAuthorizationServer,
  OakOAuth2AuthorizeRequest,
  OakOAuth2Request,
  OakOAuth2Response,
  RefreshTokenGrant,
  Router,
  Scope,
} from "./deps.ts";
import { Client } from "./models/client.ts";
import { Session } from "./models/session.ts";
import { User } from "./models/user.ts";
import {
  authorizationCodeService,
  clientService,
  sessionService,
  tokenService,
} from "./services/mod.ts";

const services = {
  clientService,
  authorizationCodeService,
  tokenService,
};

const authorizationCodeGrant = new AuthorizationCodeGrant({
  services,
  allowRefreshToken: true,
});
const clientCredentialsGrant = new ClientCredentialsGrant({ services });
const refreshTokenGrant = new RefreshTokenGrant({ services });

const oauth2Server = new AuthorizationServer({
  grants: {
    "authorization_code": authorizationCodeGrant,
    "client_credentials": clientCredentialsGrant,
    "refresh_token": refreshTokenGrant,
  },
  services,
});

async function getSession(
  request: OakOAuth2Request<Client, User, Scope>,
): Promise<Session | undefined> {
  const sessionId: string | undefined = await request.cookies.get("sessionId");
  const session: Session | undefined = sessionId
    ? await sessionService.get(sessionId)
    : undefined;
  if (!session && sessionId) request.cookies.delete("sessionId");
  return session;
}

export const oauth2 = new OakAuthorizationServer({
  server: oauth2Server,
  async getAccessToken(
    request: OakOAuth2Request<Client, User, Scope>,
  ): Promise<string | null> {
    const accessToken = await request.cookies.get("accessToken");
    return accessToken ?? null;
  },
});
export const oauth2Router = new Router();

oauth2Router.post("/token", oauth2.token());

const setAuthorization = async (
  request: OakOAuth2AuthorizeRequest<Client, User, Scope>,
): Promise<void> => {
  if (request.method === "POST") {
    const body: URLSearchParams | undefined = await request.body;
    const authorizedScopeText = body?.get("authorized_scope") ?? undefined;
    if (authorizedScopeText) {
      request.authorizedScope = new Scope(authorizedScopeText);
    }
  }

  const { clientId } = request.authorizeParameters;
  const token = await oauth2.getTokenForRequest(request)
    .catch(() => undefined);
  if (token) {
    request.user = token.user;
  }

  if (!request.user && clientId === "1000") {
    const session = await getSession(request);
    if (session?.user) {
      request.user = session.user;
    }
  }
};

const login = loginRedirectFactory<Client, User, Scope>({ loginUrl: "/login" });

const consentPage = (
  authorizeParameters: AuthorizeParameters,
) => `
  <html>
    <head>
      <title>Login</title>
    </head>
    <body>
      <form method="post">
        <input type="text" readonly name="authorized_scope" value="${
  authorizeParameters
    .scope ?? ""
}"/>
        <input type="submit" value="Consent"/>
      </form>
    </body>
  </html>
`;

const consent = async (
  request: OakOAuth2AuthorizeRequest<Client, User, Scope>,
  response: OakOAuth2Response,
): Promise<void> => {
  response.body = 401;
  response.body = consentPage(request.authorizeParameters);
  return await Promise.resolve();
};

const authorize = oauth2.authorize(setAuthorization, login, consent);
oauth2Router.get("/authorize", authorize);
oauth2Router.post("/authorize", authorize);
