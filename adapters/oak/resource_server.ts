import { ResourceServer } from "../../resource_server.ts";
import { ClientInterface } from "../../models/client.ts";
import { ScopeInterface } from "../../models/scope.ts";
import { Token } from "../../models/token.ts";
import { Context, Middleware } from "./deps.ts";
import {
  OakOAuth2Request,
  OakOAuth2Response,
  OakOAuth2ServerState,
} from "./context.ts";

export interface OakResourceServerOptions<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  /** The OAuth2 server. */
  server: ResourceServer<Client, User, Scope>;
  /** The key for storing OAuth2 state on the context's state. Defaults to "oauth2". */
  stateKey?: string;
  /**
   * Gets access token from request in a non standard way.
   * If function is not set or it resolves to null,
   * authenticate will check for access token in the authorization header or request body.
   */
  getAccessToken?: (
    request: OakOAuth2Request<Client, User, Scope>,
  ) => Promise<string | null>;
}

export class OakResourceServer<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  protected server: ResourceServer<Client, User, Scope>;
  private stateKey: string;
  private getAccessToken: (
    request: OakOAuth2Request<Client, User, Scope>,
  ) => Promise<string | null>;

  constructor(options: OakResourceServerOptions<Client, User, Scope>) {
    this.server = options.server;
    this.stateKey = options.stateKey ?? "oauth2";
    this.getAccessToken = options.getAccessToken ??
      (() => Promise.resolve(null));
  }

  protected getState(
    context: Context,
  ): OakOAuth2ServerState<Client, User, Scope> {
    const state = context.state[this.stateKey] ?? {};
    if (!context.state[this.stateKey]) {
      context.state[this.stateKey] = state;
      state.request = new OakOAuth2Request(context);
      state.response = new OakOAuth2Response(context);
    }
    return state;
  }

  async getToken(accessToken: string): Promise<Token<Client, User, Scope>> {
    return await this.server.getToken(accessToken);
  }

  async getTokenForRequest(
    request: OakOAuth2Request<Client, User, Scope>,
  ): Promise<Token<Client, User, Scope>> {
    return await this.server.getTokenForRequest(request, this.getAccessToken);
  }

  async getTokenForContext(
    context: Context,
  ): Promise<Token<Client, User, Scope>> {
    const state = this.getState(context);
    const { request } = state;
    return await this.getTokenForRequest(request);
  }

  authenticate(scope?: Scope | string): Middleware {
    const requiredScope = typeof scope === "string"
      ? this.server.Scope.from(scope)
      : scope;
    return (context: Context, next: () => Promise<unknown>) => {
      const state = this.getState(context);
      const { request, response } = state;
      return this.server.authenticate(
        request,
        response,
        next,
        this.getAccessToken,
        requiredScope,
      );
    };
  }
}

export { OakOAuth2Request, OakOAuth2Response } from "./context.ts";
export type {
  OakOAuth2AuthorizeRequest,
  OakOAuth2ServerState,
} from "./context.ts";
