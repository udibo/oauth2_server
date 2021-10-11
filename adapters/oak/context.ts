import {
  AuthorizeParameters,
  OAuth2AuthorizeRequest,
  OAuth2Request,
  OAuth2Response,
} from "../../context.ts";
import { AuthorizationCode } from "../../models/authorization_code.ts";
import { ClientInterface } from "../../models/client.ts";
import { ScopeInterface } from "../../models/scope.ts";
import { Token } from "../../models/token.ts";
import { BodyForm, Context, Cookies } from "./deps.ts";

export class OakOAuth2Request<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> implements OAuth2Request<Client, User, Scope> {
  private context: Context;
  private _bodyCached: boolean;
  private _body?: Promise<URLSearchParams>;
  authorizedScope?: Scope;
  authorizationCode?: AuthorizationCode<Client, User, Scope>;
  authorizeParameters?: AuthorizeParameters;
  user?: User;
  token?: Token<Client, User, Scope>;

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

export type OakOAuth2AuthorizeRequest<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> =
  & OakOAuth2Request<Client, User, Scope>
  & OAuth2AuthorizeRequest<Client, User, Scope>;

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

  async redirect(url: string | URL): Promise<void> {
    this.context.response.redirect(url);
    return await Promise.resolve();
  }
}

export interface OakOAuth2ServerState<
  Client extends ClientInterface,
  User,
  Scope extends ScopeInterface,
> {
  request: OakOAuth2Request<Client, User, Scope>;
  response: OakOAuth2Response;
}
