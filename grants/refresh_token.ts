import { Grant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import type { RefreshToken } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";

export interface RefreshTokenGrantInterface extends GrantInterface {
  handle(request: OAuth2Request, client: Client): Promise<RefreshToken>;
}

/**
 * The refresh token grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-6
 */
export class RefreshTokenGrant extends Grant
  implements RefreshTokenGrantInterface {
  async handle(request: OAuth2Request, client: Client): Promise<RefreshToken> {
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
      throw new InvalidGrant("refresh_token was issued to another client");
    }

    let nextToken: RefreshToken = {
      accessToken: await tokenService.generateAccessToken(client, user, scope),
      accessTokenExpiresAt: await tokenService.accessTokenExpiresAt(
        client,
        user,
        scope,
      ),
      refreshToken: await tokenService.generateRefreshToken(
        client,
        user,
        scope,
      ),
      refreshTokenExpiresAt: await tokenService.refreshTokenExpiresAt(
        client,
        user,
        scope,
      ),
      client,
      user,
      scope,
    };
    if (code) nextToken.code = code;
    nextToken = await tokenService.save(nextToken);
    await tokenService.revoke(currentToken);

    return nextToken;
  }
}
