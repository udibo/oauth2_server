import { Grant, GrantInterface, GrantOptions, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import type { Token } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import {
  AuthorizationCode,
  AuthorizationCodeServiceInterface,
} from "../models/authorization_code.ts";

export interface AuthorizationCodeGrantServices extends GrantServices {
  authorizationCodeService: AuthorizationCodeServiceInterface;
}

export interface AuthorizationCodeGrantOptions extends GrantOptions {
  services: AuthorizationCodeGrantServices;
}

export interface AuthorizationCodeGrantInterface extends GrantInterface {
  services: AuthorizationCodeGrantServices;

  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

/**
 * The authorization code grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.1
 */
export class AuthorizationCodeGrant extends Grant
  implements AuthorizationCodeGrantInterface {
  declare services: AuthorizationCodeGrantServices;

  constructor(options: AuthorizationCodeGrantOptions) {
    super(options);
  }

  // add PKCE support after finishing basic implementation
  async handle(request: OAuth2Request, client: Client): Promise<Token> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const code: string | null = body.get("code");
    if (!code) {
      throw new InvalidRequest("code parameter required");
    }

    const { authorizationCodeService, tokenService }:
      AuthorizationCodeGrantServices = this.services;
    if (await tokenService.revokeCode(code)) {
      throw new InvalidGrant("code already used");
    }

    const authorizationCode: AuthorizationCode | void =
      await authorizationCodeService.get(code);
    if (!authorizationCode) throw new InvalidGrant("invalid code");
    await authorizationCodeService.revoke(authorizationCode);

    const {
      client: authorizationCodeClient,
      user,
      scope,
      redirectUri: expectedRedirectUri,
    }: AuthorizationCode = authorizationCode;
    if (client.id !== authorizationCodeClient.id) {
      throw new InvalidGrant("code was issued to another client");
    }

    const redirectUri: string | null = body.get("redirect_uri");
    if (expectedRedirectUri) {
      if (!redirectUri) {
        throw new InvalidGrant("redirect_uri parameter required");
      } else if (redirectUri !== expectedRedirectUri) {
        throw new InvalidGrant("incorrect redirect_uri");
      }
    }

    const token: Token = await this.generateToken(client, user, scope);
    token.code = code;
    return await tokenService.save(token);
  }
}
