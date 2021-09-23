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
  username?: string;
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
    const { username } = user ?? {};
    const next: ClientInternal = {
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
      username,
    };
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
    const { username } = user ?? {};
    const current = await this.getInternal(id);
    if (!current) throw new Error("client not found");
    const next: ClientInternal = { ...current };
    if ("grants" in client) next.grants = grants;
    if ("secret" in client) next.secret = secret;
    if ("redirectUris" in client) next.redirectUris = redirectUris;
    if ("accessTokenLifetime" in client) {
      next.accessTokenLifetime = accessTokenLifetime;
    }
    if ("refreshTokenLifetime" in client) {
      next.refreshTokenLifetime = refreshTokenLifetime;
    }
    if ("user" in client) next.username = username;
    localStorage.setItem(`client:${id}`, JSON.stringify(next));
    return Promise.resolve();
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
    return internal ? this.toExternal(internal) : undefined;
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
    return internal?.username
      ? await this.userService.get(internal.username)
      : undefined;
  }
}
