import { AbstractGrant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";
import { OAuth2Request } from "../context.ts";
import { ClientInterface } from "../models/client.ts";
import { ClientServiceInterface } from "../services/client.ts";
import { Token } from "../models/token.ts";

export interface ClientCredentialsGrantServices<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantServices<Client, User, Scope> {
  clientService: ClientServiceInterface<Client, User>;
}

export interface ClientCredentialsGrantOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  services: ClientCredentialsGrantServices<Client, User, Scope>;
  Scope?: ScopeConstructor<Scope>;
}

export interface ClientCredentialsGrantInterface<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends GrantInterface<Client, User, Scope> {
  services: ClientCredentialsGrantServices<Client, User, Scope>;
}

/**
 * The client credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.4
 */
export class ClientCredentialsGrant<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface = DefaultScope,
> extends AbstractGrant<Client, User, Scope>
  implements ClientCredentialsGrantInterface<Client, User, Scope> {
  declare services: ClientCredentialsGrantServices<Client, User, Scope>;

  constructor(options: ClientCredentialsGrantOptions<Client, User, Scope>) {
    super({
      allowRefreshToken: false,
      ...options,
    });
  }

  async token(
    request: OAuth2Request<Client, User, Scope>,
    client: Client,
  ): Promise<Token<Client, User, Scope>> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const scopeText: string | null = body.get("scope");
    let scope: Scope | undefined = this.parseScope(scopeText);

    const { tokenService, clientService } = this.services;
    const user: User | void = await clientService.getUser(client);
    if (!user) throw new InvalidGrant("no user for client");

    scope = await this.acceptedScope(client, user, scope);

    const token: Token<Client, User, Scope> = await this.generateToken(
      client,
      user,
      scope,
    );
    return await tokenService.save(token);
  }
}
