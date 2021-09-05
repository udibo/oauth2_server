import { AbstractGrant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidClient, InvalidGrant, InvalidRequest } from "../errors.ts";
import type { RefreshToken, Token } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";

export interface RefreshTokenGrantOptions<Scope extends ScopeInterface> {
  services: GrantServices<Scope>;
  Scope?: ScopeConstructor<Scope>;
}

export interface RefreshTokenGrantInterface<Scope extends ScopeInterface>
  extends GrantInterface<Scope> {
  token(
    request: OAuth2Request<Scope>,
    client: Client,
  ): Promise<RefreshToken<Scope>>;
}

/**
 * The refresh token grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-6
 */
export class RefreshTokenGrant<Scope extends ScopeInterface = DefaultScope>
  extends AbstractGrant<Scope>
  implements RefreshTokenGrantInterface<Scope> {
  constructor(options: RefreshTokenGrantOptions<Scope>) {
    super({
      allowRefreshToken: true,
      ...options,
    });
  }

  async token(
    request: OAuth2Request<Scope>,
    client: Client,
  ): Promise<RefreshToken<Scope>> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const refreshToken: string | null = body.get("refresh_token");
    if (!refreshToken) {
      throw new InvalidRequest("refresh_token parameter required");
    }

    const { tokenService } = this.services;
    const currentToken: RefreshToken<Scope> | void = await tokenService
      .getRefreshToken(
        refreshToken,
      );
    if (
      !currentToken ||
      (currentToken.refreshTokenExpiresAt &&
        currentToken.refreshTokenExpiresAt < new Date())
    ) {
      throw new InvalidGrant("invalid refresh_token");
    }

    const { client: tokenClient, user, scope, code }: RefreshToken<Scope> =
      currentToken;
    if (client.id !== tokenClient.id) {
      throw new InvalidClient("refresh_token was issued to another client");
    }

    const nextToken: Token<Scope> =
      (await this.generateToken(client, user, scope));
    if (!nextToken.refreshToken) {
      nextToken.refreshToken = currentToken.refreshToken;
      if (currentToken.refreshTokenExpiresAt) {
        nextToken.refreshTokenExpiresAt = currentToken.refreshTokenExpiresAt;
      }
    }
    if (code) nextToken.code = code;
    await tokenService.revoke(currentToken);
    return await tokenService.save(nextToken) as RefreshToken<Scope>;
  }
}
