import { AbstractClientService } from "../deps.ts";
import { Client } from "../models/client.ts";
import { User } from "../models/user.ts";
import { UserService } from "./user.ts";

interface ClientInternal {
  id: string;
  secret?: string;
  grants?: string[];
  redirectUris?: string[];
  accessTokenLifetime?: number;
  refreshTokenLifetime?: number;
  userId?: string;
}

export class ClientService extends AbstractClientService<Client, User> {
  private userService: UserService;

  constructor(userService: UserService) {
    super();
    this.userService = userService;
  }

  put(client: Client): Promise<void> {
    const {
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
      user,
    } = client;
    const next: ClientInternal = { id };
    if (secret) next.secret = secret;
    if (grants) next.grants = grants;
    if (redirectUris) next.redirectUris = redirectUris;
    if (accessTokenLifetime) next.accessTokenLifetime = accessTokenLifetime;
    if (refreshTokenLifetime) next.refreshTokenLifetime = refreshTokenLifetime;
    if (user) next.userId = user.id;
    localStorage.setItem(`client:${id}`, JSON.stringify(next));
    return Promise.resolve();
  }

  async patch(client: Partial<Client> & Pick<Client, "id">): Promise<void> {
    const {
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
      user,
    } = client;
    const current = await this.getInternal(id);
    if (!current) throw new Error("client not found");
    const next: ClientInternal = { ...current, id };

    if (grants) next.grants = grants;
    else if (grants === null) delete next.grants;

    if (secret) next.secret = secret;
    else if (secret === null) delete next.secret;

    if (redirectUris) next.redirectUris = redirectUris;
    else if (redirectUris === null) delete next.redirectUris;

    if (accessTokenLifetime) {
      next.accessTokenLifetime = accessTokenLifetime;
    } else if (accessTokenLifetime === null) {
      delete next.accessTokenLifetime;
    }

    if (refreshTokenLifetime) {
      next.refreshTokenLifetime = refreshTokenLifetime;
    } else if (refreshTokenLifetime === null) {
      delete next.refreshTokenLifetime;
    }

    if (user) next.userId = user.id;
    else if (user === null) delete next.userId;

    localStorage.setItem(`client:${id}`, JSON.stringify(next));
  }

  delete(client: Client | string): Promise<boolean> {
    const clientId = typeof client === "string" ? client : client.id;
    const clientKey = `client:${clientId}`;
    const existed = !!localStorage.getItem(clientKey);
    localStorage.removeItem(clientKey);
    return Promise.resolve(existed);
  }

  private getInternal(clientId: string): Promise<ClientInternal | undefined> {
    const internalText = localStorage.getItem(`client:${clientId}`);
    return Promise.resolve(internalText ? JSON.parse(internalText) : undefined);
  }

  private toExternal(internal: ClientInternal): Promise<Client> {
    const {
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
    } = internal;
    return Promise.resolve({
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
    });
  }

  async get(clientId: string): Promise<Client | undefined> {
    const internal = await this.getInternal(clientId);
    return internal ? await this.toExternal(internal) : undefined;
  }

  async getAuthenticated(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client | undefined> {
    const internal = await this.getInternal(clientId);
    let client: Client | undefined = undefined;
    if (internal && clientSecret === internal.secret) {
      client = await this.toExternal(internal);
    }
    return client;
  }

  async getUser(client: Client | string): Promise<User | undefined> {
    const clientId = typeof client === "string" ? client : client.id;
    const internal = await this.getInternal(clientId);
    return internal?.userId
      ? await this.userService.get(internal.userId)
      : undefined;
  }
}
