import {
  InvalidRequest,
  OAuth2Error,
  UnauthorizedClient,
  UnsupportedGrantType,
} from "./errors.ts";
import { Grant } from "./grants/grant.ts";
import { Client } from "./models/client.ts";
import { Token } from "./models/token.ts";
import { Context, OAuth2Request, OAuth2Response } from "./context.ts";

export interface OAuth2ServerGrants {
  [key: string]: Grant;
}

export interface OAuth2ServerOptions {
  grants: OAuth2ServerGrants;
  realm?: string;
}

export interface BearerToken {
  "token_type": string;
  "access_token": string;
  "access_token_expires_at"?: string;
  "refresh_token"?: string;
  "refresh_token_expires_at"?: string;
  scope?: string;
}

export interface ErrorBody {
  error: string;
  "error_description"?: string;
  "error_uri"?: string;
}

export class OAuth2Server {
  realm: string;
  grants: OAuth2ServerGrants;

  constructor(options: OAuth2ServerOptions) {
    this.grants = { ...options.grants };
    this.realm = options.realm ?? "Service";
  }

  async getToken(request: OAuth2Request): Promise<Token> {
    if (request.method !== "POST") {
      throw new InvalidRequest("method must be POST");
    }

    const contentType: string | null = request.headers.get("content-type");
    if (contentType !== "application/x-www-form-urlencoded") {
      throw new InvalidRequest(
        "content-type header must be application/x-www-form-urlencoded",
      );
    }

    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const grantType: string | null = body.get("grant_type");
    if (!grantType) throw new InvalidRequest("grant_type parameter required");
    if (!this.grants[grantType]) {
      throw new UnsupportedGrantType("invalid grant_type");
    }

    const grant: Grant = this.grants[grantType];
    const client: Client = await grant.getAuthenticatedClient(request);
    if (!client.grants.includes(grantType)) {
      throw new UnauthorizedClient(
        "client is not authorized to use this grant_type",
      );
    }

    return await grant.handle(request, client);
  }

  handleError(
    response: OAuth2Response,
    error: OAuth2Error,
  ): void | Promise<void> {
    response.status = error.status ?? 500;
    if (error.status === 401) {
      response.headers.set("WWW-Authenticate", `Basic realm="${this.realm}"`);
    }
    const body: ErrorBody = {
      error: error.code ?? "server_error",
    };
    if (error.message) body.error_description = error.message;
    if (error.uri) body.error_uri = error.uri;
    response.body = body;
  }

  async token(context: Context): Promise<void> {
    const { request, response }: Context = context;
    const { headers }: OAuth2Response = response;
    headers.set("Content-Type", "application/json;charset=UTF-8");
    headers.set("Cache-Control", "no-store");
    headers.set("Pragma", "no-cache");

    try {
      const token: Token = await this.getToken(request);
      const bearerToken: BearerToken = {
        "token_type": "Bearer",
        "access_token": token.accessToken,
      };
      if (token.accessTokenExpiresAt) {
        bearerToken["access_token_expires_at"] = token.accessTokenExpiresAt
          .toJSON();
      }
      if (token.refreshToken) bearerToken["refresh_token"] = token.refreshToken;
      if (token.refreshTokenExpiresAt) {
        bearerToken["refresh_token_expires_at"] = token.refreshTokenExpiresAt
          .toJSON();
      }
      if (token.scope) bearerToken.scope = token.scope.toJSON();

      response.status = 200;
      response.body = bearerToken;
    } catch (error) {
      await this.handleError(response, error);
    }
  }
}
