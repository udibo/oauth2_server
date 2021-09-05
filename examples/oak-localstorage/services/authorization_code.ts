import { AbstractAuthorizationCodeService, Scope } from "../deps.ts";
import { AppAuthorizationCode } from "../models/authorization_code.ts";
import { ClientService } from "./client.ts";
import { UserService } from "./user.ts";

interface AuthorizationCodeInternal {
  code: string;
  expiresAt: string;
  clientId: string;
  username: string;
  scope?: string;
  redirectUri?: string;
  challenge?: string;
  challengeMethod?: string;
}

export class AuthorizationCodeService
  extends AbstractAuthorizationCodeService<Scope> {
  private clientService: ClientService;
  private userService: UserService;

  constructor(clientService: ClientService, userService: UserService) {
    super();
    this.clientService = clientService;
    this.userService = userService;
  }

  async insert(authorizationCode: AppAuthorizationCode): Promise<void> {
    if (localStorage.getItem(`authorizationCode:${authorizationCode.code}`)) {
      throw new Error("authorization code already exists");
    }
    await this.update(authorizationCode);
  }

  update(authorizationCode: AppAuthorizationCode): Promise<void> {
    const {
      code,
      expiresAt,
      client,
      user,
      scope,
      redirectUri,
      challenge,
      challengeMethod,
    } = authorizationCode;
    localStorage.setItem(
      `authorizationCode:${code}`,
      JSON.stringify({
        code,
        expiresAt: expiresAt.toJSON(),
        clientId: client.id,
        username: user.username,
        scope: scope?.toJSON(),
        redirectUri,
        challenge,
        challengeMethod,
      } as AuthorizationCodeInternal),
    );
    return Promise.resolve();
  }

  delete(authorizationCode: AppAuthorizationCode | string): Promise<boolean> {
    const code = typeof authorizationCode === "string"
      ? authorizationCode
      : authorizationCode.code;
    const codeKey = `authorizationCode:${code}`;
    const existed = !!localStorage.getItem(codeKey);
    localStorage.removeItem(codeKey);
    return Promise.resolve(existed);
  }

  async get(code: string): Promise<AppAuthorizationCode | undefined> {
    const internalText = localStorage.getItem(`authorizationCode:${code}`);
    const internal: AuthorizationCodeInternal | undefined = internalText
      ? JSON.parse(internalText)
      : undefined;
    let authorizationCode: AppAuthorizationCode | undefined = undefined;
    if (internal) {
      const {
        code,
        expiresAt,
        clientId,
        username,
        scope,
        redirectUri,
        challenge,
        challengeMethod,
      } = internal;
      const client = await this.clientService.get(clientId);
      const user = client && await this.userService.get(username);
      if (client && user) {
        authorizationCode = {
          code,
          expiresAt: new Date(expiresAt),
          client,
          user,
          redirectUri,
          challenge,
          challengeMethod,
        };
        if (scope) authorizationCode.scope = Scope.from(scope);
      } else {
        await this.delete(code);
      }
    }
    return authorizationCode;
  }

  async save(
    authorizationCode: AppAuthorizationCode,
  ): Promise<AppAuthorizationCode> {
    await this.insert(authorizationCode);
    return (await this.get(authorizationCode.code))!;
  }

  async revoke(
    authorizationCode: AppAuthorizationCode | string,
  ): Promise<boolean> {
    return await this.delete(authorizationCode);
  }
}
