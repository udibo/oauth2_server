import {
  AuthorizationCodeGrant,
  AuthorizeParameters,
  ClientCredentialsGrant,
  loginRedirectFactory,
  OakOAuth2,
  OakOAuth2AuthorizeRequest,
  OakOAuth2Response,
  OAuth2Server,
  RefreshTokenGrant,
  Router,
  Scope,
} from "./deps.ts";
import { Session } from "./models/session.ts";
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

const authorizationCodeGrant = new AuthorizationCodeGrant({ services });
const clientCredentialsGrant = new ClientCredentialsGrant({ services });
const refreshTokenGrant = new RefreshTokenGrant({ services });

const oauth2Server = new OAuth2Server({
  grants: {
    "authorization_code": authorizationCodeGrant,
    "client_credentials": clientCredentialsGrant,
    "refresh_token": refreshTokenGrant,
  },
  services,
});

export const oauth2 = new OakOAuth2({ server: oauth2Server });
export const oauth2Router = new Router();

oauth2Router.post("/token", oauth2.token());

const setAuthorization = async (
  request: OakOAuth2AuthorizeRequest<Scope>,
): Promise<void> => {
  const sessionId: string | undefined = await request.cookies.get("sessionId");
  const session: Session | undefined = sessionId
    ? await sessionService.get(sessionId)
    : undefined;
  if (session) {
    if (request.method === "POST" && request.hasBody) {
      const body: URLSearchParams | undefined = await request.body;
      const authorizedScopeText = body?.get("authorized_scope") ?? undefined;
      if (authorizedScopeText) {
        request.authorizedScope = new Scope(authorizedScopeText);
      }
    }

    const { user, accessToken } = session;
    const { clientId } = request.authorizeParameters;
    if (user && (clientId === "1000" || accessToken)) {
      request.user = user;
    }
  }
};

const login = loginRedirectFactory<Scope>({ loginUrl: "/login" });

const consentPage = (
  authorizeParameters: AuthorizeParameters,
) => `
  <html>
    <head>
      <title>Login</title>
    </head>
    <body>
      <form method="post">
        <input type="text" readonly name="authorized_scope" value="${authorizeParameters
  .scope ?? ""}"/>
        <input type="submit" value="Consent"/>
      </form>
    </body>
  </html>
`;

const consent = (
  request: OakOAuth2AuthorizeRequest<Scope>,
  response: OakOAuth2Response,
): Promise<void> => {
  response.body = 401;
  response.body = consentPage(request.authorizeParameters);
  return Promise.resolve();
};

const authorize = oauth2.authorize(setAuthorization, login, consent);
oauth2Router.get("/authorize", authorize);
oauth2Router.post("/authorize", authorize);
