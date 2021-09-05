import {
  AuthorizeParameters,
  OAuth2AuthorizeRequest,
  OAuth2Request,
  OAuth2Response,
} from "../context.ts";
import { AuthorizationCode } from "../models/authorization_code.ts";
import { ScopeInterface } from "../models/scope.ts";
import { Token } from "../models/token.ts";
import { User } from "../models/user.ts";
import { OAuth2Server } from "../server.ts";
import { BodyForm, Context, Cookies, Middleware } from "./oak_deps.ts";

export class OakOAuth2Request<Scope extends ScopeInterface>
  implements OAuth2Request<Scope> {
  private context: Context;
  private _bodyCached: boolean;
  private _body?: Promise<URLSearchParams>;
  authorizedScope?: Scope;
  authorizationCode?: AuthorizationCode<Scope>;
  authorizeParameters?: AuthorizeParameters;
  user?: User;
  token?: Token<Scope>;

  constructor(context: Context) {
    this.context = context;
    this._bodyCached = false;
  }

  get url(): URL {
    return this.context.request.url;
  }

  get headers(): Headers {
    return this.context.request.headers;
  }

  get method(): string {
    return this.context.request.method;
  }

  get hasBody(): boolean {
    return this.context.request.hasBody;
  }

  get body(): Promise<URLSearchParams> | undefined {
    if (!this._bodyCached) {
      try {
        const body: BodyForm = this.context.request.body({ type: "form" });
        this._body = body.type === "form"
          ? body.value.catch(() => new URLSearchParams())
          : undefined;
      } catch {
        this._body = undefined;
      }
      this._bodyCached = true;
    }
    return this._body;
  }

  get cookies(): Cookies {
    return this.context.cookies;
  }
}

export type OakOAuth2AuthorizeRequest<Scope extends ScopeInterface> =
  & OakOAuth2Request<Scope>
  & OAuth2AuthorizeRequest<Scope>;

export class OakOAuth2Response implements OAuth2Response {
  private context: Context;
  // deno-lint-ignore no-explicit-any
  private _body: any | Promise<any>;

  constructor(context: Context) {
    this.context = context;
  }

  get status(): number {
    return this.context.response.status;
  }
  set status(value: number) {
    this.context.response.status = value;
  }

  get headers(): Headers {
    return this.context.response.headers;
  }
  set headers(value: Headers) {
    this.context.response.headers = value;
  }

  // deno-lint-ignore no-explicit-any
  get body(): any | Promise<any> | (() => (any | Promise<any>)) {
    return this._body;
  }
  // deno-lint-ignore no-explicit-any
  set body(value: any | Promise<any> | (() => (any | Promise<any>))) {
    this.context.response.body = Promise.resolve(value) === value
      ? () => value
      : value;
    this._body = value;
  }

  redirect(url: string | URL): Promise<void> {
    this.context.response.redirect(url);
    return Promise.resolve();
  }
}

export interface OakOAuth2Options<Scope extends ScopeInterface> {
  /** The OAuth2 server. */
  server: OAuth2Server<Scope>;
  /** The key for storing OAuth2 state on the context's state. Defaults to "oauth2". */
  stateKey?: string;
}

export interface OakOAuth2State<Scope extends ScopeInterface> {
  request: OakOAuth2Request<Scope>;
  response: OakOAuth2Response;
  token?: Token<Scope>;
  authorizationCode?: AuthorizationCode<Scope>;
}
export class OakOAuth2<Scope extends ScopeInterface> {
  private server: OAuth2Server<Scope>;
  private stateKey: string;

  constructor(options: OakOAuth2Options<Scope>) {
    this.server = options.server;
    this.stateKey = options.stateKey ?? "oauth2";
  }

  protected getState(context: Context): OakOAuth2State<Scope> {
    const state = context.state[this.stateKey] ?? {};
    if (!context.state[this.stateKey]) {
      context.state[this.stateKey] = state;
      state.request = new OakOAuth2Request(context);
      state.response = new OakOAuth2Response(context);
    }
    return state;
  }

  token(): Middleware {
    return async (context: Context) => {
      const state = this.getState(context);
      const { request, response } = state;
      await this.server.token(request, response);
      const { token } = request;
      if (token) state.token = token;
    };
  }

  authorize(
    setAuthorization: (
      request: OakOAuth2AuthorizeRequest<Scope>,
    ) => Promise<void>,
    login: (
      request: OakOAuth2AuthorizeRequest<Scope>,
      response: OakOAuth2Response,
    ) => Promise<void>,
    consent?: (
      request: OakOAuth2AuthorizeRequest<Scope>,
      response: OakOAuth2Response,
    ) => Promise<void>,
  ): Middleware {
    return async (context: Context) => {
      const state = this.getState(context);
      const { request, response } = state;
      await this.server.authorize(
        request,
        response,
        setAuthorization,
        login,
        consent,
      );
      const { authorizationCode } = request;
      if (authorizationCode) state.authorizationCode = authorizationCode;
    };
  }

  authenticate(scope?: Scope | string): Middleware {
    const requiredScope = typeof scope === "string"
      ? this.server.Scope.from(scope)
      : scope;
    return async (context: Context, next: () => Promise<unknown>) => {
      const state = this.getState(context);
      const { request, response } = state;
      await this.server.authenticate(request, response, next, requiredScope);
      const { token } = request;
      if (token) state.token = token;
    };
  }
}
