import { AbstractGrant, GrantInterface, GrantServices } from "./grant.ts";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
} from "../errors.ts";
import type { RefreshToken } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { ClientInterface } from "../models/client.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";

export interface RefreshTokenGrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services: GrantServices<Client, User, Scope>;
  Scope?: ScopeConstructor<Scope>;
}

export interface RefreshTokenGrantInterface<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantInterface<Client, User, Scope> {
  token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<RefreshToken<Client, User, Scope>>;
}

/**
 * The refresh token grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-6
 */
export class RefreshTokenGrant<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> extends AbstractGrant<Client, User, Scope>
  implements RefreshTokenGrantInterface<Client, User, Scope> {
  constructor(options: RefreshTokenGrantOptions<Client, User, Scope>) {
    super({
      allowRefreshToken: true,
      ...options,
    });
  }

  async token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<RefreshToken<Client, User, Scope>> {
    if (!request.hasBody) {
      throw new InvalidRequestError("request body required");
    }

    const body: URLSearchParams = await request.body!;
    const refreshToken: string | null = body.get("refresh_token");
    if (!refreshToken) {
      throw new InvalidRequestError("refresh_token parameter required");
    }

    const { tokenService } = this.services;
    const currentToken = await tokenService.getRefreshToken(refreshToken);
    if (
      !currentToken ||
      (currentToken.refreshTokenExpiresAt &&
        currentToken.refreshTokenExpiresAt < new Date())
    ) {
      throw new InvalidGrantError("invalid refresh_token");
    }

    const { client: tokenClient, user, scope, code } = currentToken;
    if (client.id !== tokenClient.id) {
      throw new InvalidClientError(
        "refresh_token was issued to another client",
      );
    }

    const nextToken = await this.generateToken(client, user, scope);
    if (!nextToken.refreshToken) {
      nextToken.refreshToken = currentToken.refreshToken;
      if (currentToken.refreshTokenExpiresAt) {
        nextToken.refreshTokenExpiresAt = currentToken.refreshTokenExpiresAt;
      }
    }
    if (code) nextToken.code = code;
    await tokenService.revoke(currentToken);
    return await tokenService.save(nextToken) as RefreshToken<
      Client,
      User,
      Scope
    >;
  }
}
