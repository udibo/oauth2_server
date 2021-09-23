import {
  AbstractAuthorizationCodeService,
  AuthorizationCode,
  Scope,
} from "../deps.ts";
import { Client } from "../models/client.ts";
import { User } from "../models/user.ts";
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
  extends AbstractAuthorizationCodeService<Client, User, Scope> {
  private clientService: ClientService;
  private userService: UserService;

  constructor(clientService: ClientService, userService: UserService) {
    super();
    this.clientService = clientService;
    this.userService = userService;
  }

  put(
    authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<void> {
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
    const next: AuthorizationCodeInternal = {
      code,
      expiresAt: expiresAt.toJSON(),
      clientId: client.id,
      username: user.username,
      scope: scope?.toJSON(),
      redirectUri,
      challenge,
      challengeMethod,
    };
    localStorage.setItem(`authorizationCode:${code}`, JSON.stringify(next));
    return Promise.resolve();
  }

  delete(
    authorizationCode: AuthorizationCode<Client, User, Scope> | string,
  ): Promise<boolean> {
    const code = typeof authorizationCode === "string"
      ? authorizationCode
      : authorizationCode.code;
    const codeKey = `authorizationCode:${code}`;
    const existed = !!localStorage.getItem(codeKey);
    localStorage.removeItem(codeKey);
    return Promise.resolve(existed);
  }

  async get(
    code: string,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined> {
    const internalText = localStorage.getItem(`authorizationCode:${code}`);
    const internal: AuthorizationCodeInternal | undefined = internalText
      ? JSON.parse(internalText)
      : undefined;
    let authorizationCode: AuthorizationCode<Client, User, Scope> | undefined =
      undefined;
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
    authorizationCode: AuthorizationCode<Client, User, Scope>,
  ): Promise<AuthorizationCode<Client, User, Scope>> {
    await this.put(authorizationCode);
    return (await this.get(authorizationCode.code))!;
  }

  async revoke(
    authorizationCode: AuthorizationCode<Client, User, Scope> | string,
  ): Promise<boolean> {
    return await this.delete(authorizationCode);
  }
}
