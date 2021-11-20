import {
  AbstractGrant,
  GrantInterface,
  GrantOptions,
  GrantServices,
} from "./grant.ts";
import { InvalidGrantError, InvalidRequestError } from "../errors.ts";
import { Scope as DefaultScope, ScopeInterface } from "../models/scope.ts";
import { UserServiceInterface } from "../services/user.ts";
import { OAuth2Request } from "../context.ts";
import { ClientInterface } from "../models/client.ts";
import { Token } from "../models/token.ts";

export interface PasswordGrantServices<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantServices<Client, User, Scope> {
  userService: UserServiceInterface<User>;
}

export interface PasswordGrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantOptions<Client, User, Scope> {
  services: PasswordGrantServices<Client, User, Scope>;
}

export interface PasswordGrantInterface<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantInterface<Client, User, Scope> {
  services: PasswordGrantServices<Client, User, Scope>;
}

/**
 * The resource owner password credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.3
 * Usage of this grant type is not recommended.
 * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4
 */
export class PasswordGrant<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> extends AbstractGrant<Client, User, Scope>
  implements PasswordGrantInterface<Client, User, Scope> {
  declare services: PasswordGrantServices<Client, User, Scope>;

  constructor(options: PasswordGrantOptions<Client, User, Scope>) {
    super(options);
  }

  async token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<Token<Client, User, Scope>> {
    const body: URLSearchParams = await request.body;
    const scopeText: string | null = body.get("scope");
    let scope: Scope | null | undefined = this.parseScope(scopeText);

    const username: string | null = body.get("username");
    if (!username) throw new InvalidRequestError("username parameter required");
    const password: string | null = body.get("password");
    if (!password) throw new InvalidRequestError("password parameter required");

    const { tokenService, userService } = this.services;
    const user: User | void = await userService.getAuthenticated(
      username,
      password,
    );
    if (!user) throw new InvalidGrantError("user authentication failed");

    scope = await this.acceptedScope(client, user, scope);

    const token = await this.generateToken(client, user, scope);
    return await tokenService.save(token);
  }
}
