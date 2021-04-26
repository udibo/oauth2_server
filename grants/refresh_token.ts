import { Grant, GrantServices } from "./grant.ts";
import type { RefreshToken } from "../models/token.ts";

export class RefreshTokenGrant extends Grant {
  async handle(refreshToken: string): Promise<RefreshToken> {
    const { token }: GrantServices = this.services;
    const currentToken: RefreshToken | void = await token.getRefreshToken(
      refreshToken,
    );
    if (!currentToken) throw new Error("refresh token not found");

    const { client, user, scope }: RefreshToken = currentToken;
    if (!client.grants.includes("refresh_token")) {
      throw new Error("refresh_token grant type not allowed for the client");
    }

    const nextToken: RefreshToken = await token.save({
      accessToken: await token.generateAccessToken(client, user, scope),
      accessTokenExpiresAt: await token.accessTokenExpiresAt(
        client,
        user,
        scope,
      ),
      refreshToken: await token.generateRefreshToken(client, user, scope),
      refreshTokenExpiresAt: await token.refreshTokenExpiresAt(
        client,
        user,
        scope,
      ),
      client,
      user,
      scope,
    });
    await token.revoke(currentToken);

    return nextToken;
  }
}
