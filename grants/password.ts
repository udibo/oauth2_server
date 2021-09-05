import {
  AbstractGrant,
  GrantInterface,
  GrantOptions,
  GrantServices,
} from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import { Scope as DefaultScope, ScopeInterface } from "../models/scope.ts";
import { User } from "../models/user.ts";
import { UserServiceInterface } from "../services/user.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { Token } from "../models/token.ts";

export interface PasswordGrantServices<Scope extends ScopeInterface>
  extends GrantServices<Scope> {
  userService: UserServiceInterface;
}

export interface PasswordGrantOptions<Scope extends ScopeInterface>
  extends GrantOptions<Scope> {
  services: PasswordGrantServices<Scope>;
}

export interface PasswordGrantInterface<Scope extends ScopeInterface>
  extends GrantInterface<Scope> {
  services: PasswordGrantServices<Scope>;
}

/**
 * The resource owner password credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.3
 * Usage of this grant type is not recommended.
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4
 */
export class PasswordGrant<Scope extends ScopeInterface = DefaultScope>
  extends AbstractGrant<Scope>
  implements PasswordGrantInterface<Scope> {
  declare services: PasswordGrantServices<Scope>;

  constructor(options: PasswordGrantOptions<Scope>) {
    super(options);
  }

  async token(
    request: OAuth2Request<Scope>,
    client: Client,
  ): Promise<Token<Scope>> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const scopeText: string | null = body.get("scope");
    let scope: Scope | undefined = this.parseScope(scopeText);

    const username: string | null = body.get("username");
    if (!username) throw new InvalidRequest("username parameter required");
    const password: string | null = body.get("password");
    if (!password) throw new InvalidRequest("password parameter required");

    const { tokenService, userService } = this.services;
    const user: User | void = await userService.getAuthenticated(
      username,
      password,
    );
    if (!user) throw new InvalidGrant("user authentication failed");

    scope = await this.acceptedScope(client, user, scope);

    const token: Token<Scope> = await this.generateToken(client, user, scope);
    return await tokenService.save(token);
  }
}
