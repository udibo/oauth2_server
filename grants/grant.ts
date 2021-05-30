import { Client } from "../models/client.ts";
import type { Token, TokenServiceInterface } from "../models/token.ts";
import { OAuth2Request } from "../context.ts";
import { Scope, ScopeInterface } from "../models/scope.ts";

export interface GrantServices {
  tokenService: TokenServiceInterface;
}

export interface GrantOptions {
  services: GrantServices;
}

export interface GrantInterface {
  services: GrantServices;
  parseScope(scopeText?: string | null): ScopeInterface | undefined;
  handle(request: OAuth2Request, client: Client): Promise<Token>;
}

export abstract class Grant implements GrantInterface {
  services: GrantServices;

  constructor(options: GrantOptions) {
    this.services = { ...options.services };
  }

  parseScope(scopeText?: string | null): ScopeInterface | undefined {
    return scopeText ? new Scope(scopeText) : undefined;
  }

  abstract handle(request: OAuth2Request, client: Client): Promise<Token>;
}
