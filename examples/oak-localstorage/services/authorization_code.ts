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
  userId: string;
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

  async put(
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
      userId: user.id,
    };
    if (scope) next.scope = scope.toJSON();
    if (redirectUri) next.redirectUri = redirectUri;
    if (challenge) next.challenge = challenge;
    if (challengeMethod) next.challengeMethod = challengeMethod;
    localStorage.setItem(`authorizationCode:${code}`, JSON.stringify(next));
    return await Promise.resolve();
  }

  async patch(
    authorizationCode:
      & Partial<AuthorizationCode<Client, User, Scope>>
      & Pick<AuthorizationCode<Client, User, Scope>, "code">,
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
    const current = await this.getInternal(code);
    if (!current) throw new Error("authorization code not found");
    const next: AuthorizationCodeInternal = { ...current, code };

    if (expiresAt) next.expiresAt = expiresAt.toJSON();
    if (client) next.clientId = client.id;
    if (user) next.userId = user.id;

    if (scope) next.scope = scope.toJSON();
    else if (scope === null) delete next.scope;

    if (redirectUri) next.redirectUri = redirectUri;
    else if (redirectUri === null) delete next.redirectUri;

    if (challenge) next.challenge = challenge;
    else if (challenge === null) delete next.challenge;

    if (challengeMethod) next.challengeMethod = challengeMethod;
    else if (challengeMethod === null) delete next.challengeMethod;

    localStorage.setItem(`authorizationCode:${code}`, JSON.stringify(next));
  }

  async delete(
    authorizationCode: AuthorizationCode<Client, User, Scope> | string,
  ): Promise<boolean> {
    const code = typeof authorizationCode === "string"
      ? authorizationCode
      : authorizationCode.code;
    const codeKey = `authorizationCode:${code}`;
    const existed = !!localStorage.getItem(codeKey);
    localStorage.removeItem(codeKey);
    return await Promise.resolve(existed);
  }

  private async getInternal(
    code: string,
  ): Promise<AuthorizationCodeInternal | undefined> {
    const internalText = localStorage.getItem(`authorizationCode:${code}`);
    return await Promise.resolve(
      internalText ? JSON.parse(internalText) : undefined,
    );
  }

  private async toExternal(
    internal: AuthorizationCodeInternal,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined> {
    const {
      code,
      expiresAt,
      clientId,
      userId,
      scope,
      redirectUri,
      challenge,
      challengeMethod,
    } = internal;
    const client = await this.clientService.get(clientId);
    const user = client && await this.userService.get(userId);
    if (client && user) {
      const authorizationCode: AuthorizationCode<Client, User, Scope> = {
        code,
        expiresAt: new Date(expiresAt),
        client,
        user,
        redirectUri,
        challenge,
        challengeMethod,
      };
      if (scope) authorizationCode.scope = Scope.from(scope);
      return authorizationCode;
    } else {
      await this.delete(code);
    }
  }

  async get(
    code: string,
  ): Promise<AuthorizationCode<Client, User, Scope> | undefined> {
    const internal = await this.getInternal(code);
    return internal ? await this.toExternal(internal) : undefined;
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
