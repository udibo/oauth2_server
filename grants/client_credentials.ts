import { AbstractGrant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import {
  Scope as DefaultScope,
  ScopeConstructor,
  ScopeInterface,
} from "../models/scope.ts";
import { User } from "../models/user.ts";
import { OAuth2Request } from "../context.ts";
import { Client } from "../models/client.ts";
import { ClientServiceInterface } from "../services/client.ts";
import { Token } from "../models/token.ts";

export interface ClientCredentialsGrantServices<Scope extends ScopeInterface>
  extends GrantServices<Scope> {
  clientService: ClientServiceInterface;
}

export interface ClientCredentialsGrantOptions<Scope extends ScopeInterface> {
  services: ClientCredentialsGrantServices<Scope>;
  Scope?: ScopeConstructor<Scope>;
}

export interface ClientCredentialsGrantInterface<Scope extends ScopeInterface>
  extends GrantInterface<Scope> {
  services: ClientCredentialsGrantServices<Scope>;
}

/**
 * The client credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.4
 */
export class ClientCredentialsGrant<Scope extends ScopeInterface = DefaultScope>
  extends AbstractGrant<Scope>
  implements ClientCredentialsGrantInterface<Scope> {
  declare services: ClientCredentialsGrantServices<Scope>;

  constructor(options: ClientCredentialsGrantOptions<Scope>) {
    super({
      allowRefreshToken: false,
      ...options,
    });
  }

  async token(
    request: OAuth2Request<Scope>,
    client: Client,
  ): Promise<Token<Scope>> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const scopeText: string | null = body.get("scope");
    let scope: Scope | undefined = this.parseScope(scopeText);

    const { tokenService, clientService } = this.services;
    const user: User | void = await clientService.getUser(client);
    if (!user) throw new InvalidGrant("no user for client");

    scope = await this.acceptedScope(client, user, scope);

    const token: Token<Scope> = await this.generateToken(client, user, scope);
    return await tokenService.save(token);
  }
}
