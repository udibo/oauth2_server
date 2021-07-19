import { Grant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidClient, InvalidGrant, InvalidRequest } from "../errors.ts";
import type { RefreshToken, Token } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { ScopeConstructor } from "../models/scope.ts";

export interface RefreshTokenGrantOptions {
  services: GrantServices;
  Scope?: ScopeConstructor;
}

export interface RefreshTokenGrantInterface extends GrantInterface {
  token(request: OAuth2Request, client: Client): Promise<RefreshToken>;
}

/**
 * The refresh token grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-6
 */
export class RefreshTokenGrant extends Grant
  implements RefreshTokenGrantInterface {
  constructor(options: RefreshTokenGrantOptions) {
    super({
      allowRefreshToken: true,
      ...options,
    });
  }

  async token(request: OAuth2Request, client: Client): Promise<RefreshToken> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const refreshToken: string | null = body.get("refresh_token");
    if (!refreshToken) {
      throw new InvalidRequest("refresh_token parameter required");
    }

    const { tokenService }: GrantServices = this.services;
    const currentToken: RefreshToken | void = await tokenService
      .getRefreshToken(
        refreshToken,
      );
    if (!currentToken) throw new InvalidGrant("invalid refresh_token");

    const { client: tokenClient, user, scope, code }: RefreshToken =
      currentToken;
    if (client.id !== tokenClient.id) {
      throw new InvalidClient("refresh_token was issued to another client");
    }

    const nextToken: Token = (await this.generateToken(client, user, scope));
    if (!nextToken.refreshToken) {
      nextToken.refreshToken = currentToken.refreshToken;
      if (currentToken.refreshTokenExpiresAt) {
        nextToken.refreshTokenExpiresAt = currentToken.refreshTokenExpiresAt;
      }
    }
    if (code) nextToken.code = code;
    await tokenService.revoke(currentToken);
    return await tokenService.save(nextToken as RefreshToken);
  }
}
