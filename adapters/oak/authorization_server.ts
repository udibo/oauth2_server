import { AuthorizationServer } from "../../authorization_server.ts";
import { ClientInterface } from "../../models/client.ts";
import { ScopeInterface } from "../../models/scope.ts";
import { Context, Middleware } from "./deps.ts";
import { OakOAuth2AuthorizeRequest, OakOAuth2Response } from "./context.ts";
import {
  OakResourceServer,
  OakResourceServerOptions,
} from "./resource_server.ts";

export interface OakAuthorizationServerOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends OakResourceServerOptions<Client, User, Scope> {
  /** The OAuth2 server. */
  server: AuthorizationServer<Client, User, Scope>;
}

export class OakAuthorizationServer<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> extends OakResourceServer<Client, User, Scope> {
  protected server: AuthorizationServer<Client, User, Scope>;

  constructor(options: OakAuthorizationServerOptions<Client, User, Scope>) {
    super(options);
    this.server = options.server;
  }

  token(): Middleware {
    return async (context: Context) => {
      const state = this.getState(context);
      const { request, response } = state;
      return await this.server.token(request, response);
    };
  }

  authorize(
    setAuthorization: (
      request: OakOAuth2AuthorizeRequest<Client, User, Scope>,
    ) => Promise<void>,
    login: (
      request: OakOAuth2AuthorizeRequest<Client, User, Scope>,
      response: OakOAuth2Response,
    ) => Promise<void>,
    consent?: (
      request: OakOAuth2AuthorizeRequest<Client, User, Scope>,
      response: OakOAuth2Response,
    ) => Promise<void>,
  ): Middleware {
    return (context: Context) => {
      const state = this.getState(context);
      const { request, response } = state;
      return this.server.authorize(
        request,
        response,
        setAuthorization,
        login,
        consent,
      );
    };
  }
}

export {
  OakOAuth2Request,
  OakOAuth2Response,
  OakResourceServer,
} from "./resource_server.ts";
export type {
  OakOAuth2AuthorizeRequest,
  OakOAuth2ServerState,
  OakResourceServerOptions,
} from "./resource_server.ts";
