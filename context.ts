import { AuthorizationCode } from "./models/authorization_code.ts";
import { ScopeInterface } from "./models/scope.ts";
import { Token } from "./models/token.ts";
import { User } from "./models/user.ts";

export interface OAuth2Request<Scope extends ScopeInterface> {
  url: URL;
  headers: Headers;
  method: string;
  hasBody: boolean;
  body?: Promise<URLSearchParams>;
  token?: Token<Scope>;
  authorizationCode?: AuthorizationCode<Scope>;
  authorizeParameters?: AuthorizeParameters;
  authorizedScope?: Scope;
  redirectUrl?: URL;
  user?: User;
  acceptedScope?: Scope;
  requestedScope?: Scope;
}

export interface OAuth2AuthenticatedRequest<Scope extends ScopeInterface>
  extends OAuth2Request<Scope> {
  token: Token<Scope>;
}

export interface OAuth2AuthorizeRequest<Scope extends ScopeInterface>
  extends OAuth2Request<Scope> {
  authorizeParameters: AuthorizeParameters;
}

export interface OAuth2AuthorizedRequest<Scope extends ScopeInterface>
  extends OAuth2AuthorizeRequest<Scope> {
  authorizationCode: AuthorizationCode<Scope>;
  redirectUrl: URL;
}

export interface OAuth2Response {
  status?: number;
  headers: Headers;
  // deno-lint-ignore no-explicit-any
  body?: any | Promise<any> | (() => (any | Promise<any>));
  redirect(url: string | URL): Promise<void>;
}

export interface ErrorBody {
  error: string;
  "error_description"?: string;
  "error_uri"?: string;
}

const BEARER_TOKEN = /^ *(?:[Bb][Ee][Aa][Rr][Ee][Rr]) +([\w-.~+/]+=*) *$/;

export async function getAccessToken<Scope extends ScopeInterface>(
  request: OAuth2Request<Scope>,
): Promise<string | null> {
  let accessToken: string | null = null;

  const authorization = request.headers.get("authorization");
  if (authorization) {
    const match = BEARER_TOKEN.exec(authorization);
    if (match) accessToken = match[1];
  }

  if (!accessToken) {
    const contentType: string | null = request.headers.get(
      "content-type",
    );
    if (
      request.method === "POST" &&
      contentType === "application/x-www-form-urlencoded"
    ) {
      const body: URLSearchParams = await request.body!;
      accessToken = body.get("access_token");
    }
  }

  return accessToken;
}

export interface AuthorizeParameters {
  responseType: string | null;
  clientId: string | null;
  redirectUri: string | null;
  state: string | null;
  scope: string | null;
  challenge: string | null;
  challengeMethod: string | null;
}

/** Gets the authorize parameters from the request. */
export async function authorizeParameters<Scope extends ScopeInterface>(
  request: OAuth2Request<Scope>,
): Promise<AuthorizeParameters> {
  let responseType: string | null = null;
  let clientId: string | null = null;
  let redirectUri: string | null = null;
  let state: string | null = null;
  let scope: string | null = null;
  let challenge: string | null = null;
  let challengeMethod: string | null = null;

  if (request.method === "POST") {
    const contentType: string | null = request.headers.get("content-type");
    if (
      contentType === "application/x-www-form-urlencoded" && request.hasBody
    ) {
      const body: URLSearchParams = await request.body!;
      responseType = body.get("response_type");
      clientId = body.get("client_id");
      redirectUri = body.get("redirect_uri");
      state = body.get("state");
      scope = body.get("scope");
      challenge = body.get("code_challenge");
      challengeMethod = body.get("code_challenge_method");
    }
  }

  const url: URL = request.url;
  const { searchParams } = url;

  if (!responseType) responseType = searchParams.get("response_type");
  if (!clientId) clientId = searchParams.get("client_id");
  if (!redirectUri) redirectUri = searchParams.get("redirect_uri");
  if (!state) state = searchParams.get("state");
  if (!scope) scope = searchParams.get("scope");
  if (!challenge) challenge = searchParams.get("code_challenge");
  if (!challengeMethod) {
    challengeMethod = searchParams.get("code_challenge_method");
  }

  return {
    responseType,
    clientId,
    redirectUri,
    state,
    scope,
    challenge,
    challengeMethod,
  };
}

/** Generates url for an authorization get request. */
export function authorizeUrl<Scope extends ScopeInterface>(
  request: OAuth2AuthorizeRequest<Scope>,
): URL {
  const getUrl: URL = new URL(request.url.toString());
  getUrl.search = "";
  const { searchParams } = getUrl;
  const {
    responseType,
    clientId,
    redirectUri,
    state,
    scope,
    challenge,
    challengeMethod,
  } = request.authorizeParameters;
  if (responseType) searchParams.set("response_type", responseType);
  if (clientId) searchParams.set("client_id", clientId);
  if (redirectUri) searchParams.set("redirect_uri", redirectUri);
  if (state) searchParams.set("state", state);
  if (scope) searchParams.set("scope", scope);
  if (challenge) searchParams.set("code_challenge", challenge);
  if (challengeMethod) {
    searchParams.set("code_challenge_method", challengeMethod);
  }
  return getUrl;
}

export interface LoginRedirectOptions {
  /** The url for logging in when unauthenticated. */
  loginUrl: string | URL;
  /** The search parameter key for the url to redirect to after logging in. Defaults to "redirect_url". */
  loginRedirectKey?: string;
}

export function loginRedirectFactory<Scope extends ScopeInterface>(
  options: LoginRedirectOptions,
) {
  const { loginUrl } = options;
  const loginRedirectKey = options.loginRedirectKey ?? "redirect_uri";

  return async (
    request: OAuth2AuthorizeRequest<Scope>,
    response: OAuth2Response,
  ) => {
    if (typeof loginUrl === "string") {
      const queryIndex: number = loginUrl.indexOf("?");
      let pathname: string;
      let searchParams: URLSearchParams;
      if (queryIndex === -1) {
        pathname = loginUrl;
        searchParams = new URLSearchParams();
      } else {
        pathname = loginUrl.slice(0, queryIndex);
        searchParams = new URLSearchParams(loginUrl.slice(queryIndex));
      }
      searchParams.set(
        loginRedirectKey,
        authorizeUrl(request).toString(),
      );
      response.redirect(`${pathname}?${searchParams.toString()}`);
    } else {
      const target = new URL(loginUrl.toString());
      const searchParams = target.searchParams;
      searchParams.set(
        loginRedirectKey,
        authorizeUrl(request).toString(),
      );
      await response.redirect(target);
    }
  };
}
