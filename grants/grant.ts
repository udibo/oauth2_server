import type { TokenServiceInterface } from "../models/token.ts";

export interface GrantServices {
  token: TokenServiceInterface;
}

export interface GrantOptions {
  services: GrantServices;
}

export abstract class Grant {
  protected services: GrantServices;

  constructor(options: GrantOptions) {
    this.services = {
      token: options.services.token,
    };
  }
}
