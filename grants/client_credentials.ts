import { Grant, GrantInterface, GrantServices } from "./grant.ts";
import { InvalidGrant, InvalidRequest } from "../errors.ts";
import { ScopeInterface } from "../models/scope.ts";
import type { User } from "../models/user.ts";
import { OAuth2Request } from "../context.ts";
import { Client, ClientServiceInterface } from "../models/client.ts";
import { Token } from "../models/token.ts";

export interface ClientCredentialsGrantServices extends GrantServices {
  clientService: ClientServiceInterface;
}

export interface ClientCredentialsGrantOptions {
  services: ClientCredentialsGrantServices;
}

export interface ClientCredentialsGrantInterface extends GrantInterface {
  services: ClientCredentialsGrantServices;

  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

/**
 * The client credentials grant type.
 * https://datatracker.ietf.org/doc/html/rfc6749.html#section-4.4
 */
export class ClientCredentialsGrant extends Grant
  implements ClientCredentialsGrantInterface {
  declare services: ClientCredentialsGrantServices;

  constructor(options: ClientCredentialsGrantOptions) {
    super({
      allowRefreshToken: false,
      ...options,
    });
  }

  async handle(request: OAuth2Request, client: Client): Promise<Token> {
    if (!request.hasBody) throw new InvalidRequest("request body required");

    const body: URLSearchParams = await request.body!;
    const scopeText: string | null = body.get("scope");
    const scope: ScopeInterface | undefined = this.parseScope(scopeText);

    const { tokenService, clientService }: ClientCredentialsGrantServices =
      this.services;
    const user: User | void = await clientService.getUser(client);
    if (!user) throw new InvalidGrant("no user for client");

    const token: Token = await this.generateToken(client, user, scope);
    return await tokenService.save(token);
  }
}
