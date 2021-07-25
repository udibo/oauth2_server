import { OAuth2Request, OAuth2Response } from "../context.ts";
import { BodyForm, Request, Response } from "./oak_deps.ts";

export class OakOAuth2Request implements OAuth2Request {
  private oak: Request;
  private _bodyCached: boolean;
  private _body?: Promise<URLSearchParams>;

  constructor(request: Request) {
    this.oak = request;
    this._bodyCached = false;
  }

  get url(): URL {
    return this.oak.url;
  }

  get headers(): Headers {
    return this.oak.headers;
  }

  get method(): string {
    return this.oak.method;
  }

  get hasBody(): boolean {
    return this.oak.hasBody;
  }

  get body(): Promise<URLSearchParams> | undefined {
    if (!this._bodyCached) {
      try {
        const body: BodyForm = this.oak.body({ type: "form" });
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
}

export class OakOAuth2Response implements OAuth2Response {
  private oak: Response;
  // deno-lint-ignore no-explicit-any
  private _body: any | Promise<any>;

  constructor(response: Response) {
    this.oak = response;
  }

  get status(): number {
    return this.oak.status;
  }
  set status(value: number) {
    this.oak.status = value;
  }

  get headers(): Headers {
    return this.oak.headers;
  }
  set headers(value: Headers) {
    this.oak.headers = value;
  }

  // deno-lint-ignore no-explicit-any
  get body(): any | Promise<any> | (() => (any | Promise<any>)) {
    return this._body;
  }
  // deno-lint-ignore no-explicit-any
  set body(value: any | Promise<any> | (() => (any | Promise<any>))) {
    this.oak.body = Promise.resolve(value) === value ? () => value : value;
    this._body = value;
  }

  redirect(url: string | URL): void {
    this.oak.redirect(url);
  }
}