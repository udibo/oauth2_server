import { Grant, GrantInterface, GrantOptions, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import { ScopeInterface } from "../models/scope.ts";
import type { User, UserServiceInterface } from "../models/user.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { Token } from "../models/token.ts";

export interface PasswordGrantServices extends GrantServices {
  userService: UserServiceInterface;
}

export interface PasswordGrantOptions extends GrantOptions {
  services: PasswordGrantServices;
}

export interface PasswordGrantInterface extends GrantInterface {
  services: PasswordGrantServices;

  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

/**
 * The resource owner password credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.3
 * Usage of this grant type is not recommended.
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4
 */
export class PasswordGrant extends Grant implements PasswordGrantInterface {
  declare services: PasswordGrantServices;

  constructor(options: PasswordGrantOptions) {
    super(options);
  }

  async handle(request: OAuth2Request, client: Client): Promise<Token> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const scopeText: string | null = body.get("scope");
    const scope: ScopeInterface | undefined = this.parseScope(scopeText);
    const username: string | null = body.get("username");
    if (!username) throw new InvalidRequest("username parameter required");
    const password: string | null = body.get("password");
    if (!password) throw new InvalidRequest("password parameter required");

    const { tokenService, userService }: PasswordGrantServices = this.services;
    const user: User | void = await userService.getAuthenticated(
      username,
      password,
    );
    if (!user) throw new InvalidGrant("user authentication failed");

    const token: Token = await this.generateToken(client, user, scope);
    return await tokenService.save(token);
  }
}
