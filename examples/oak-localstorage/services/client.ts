import { AbstractClientService } from "../deps.ts";
import { AppClient } from "../models/client.ts";
import { AppUser } from "../models/user.ts";
import { UserService } from "./user.ts";

interface ClientInternal {
  id: string;
  secret: string;
  grants: string[];
  redirectUris?: string[];
  accessTokenLifetime?: number;
  refreshTokenLifetime?: number;
  username?: string;
}

export class ClientService extends AbstractClientService {
  private userService: UserService;

  constructor(userService: UserService) {
    super();
    this.userService = userService;
  }

  async insert(client: AppClient): Promise<void> {
    if (localStorage.getItem(`client:${client.id}`)) {
      throw new Error("client already exists");
    }
    await this.update(client);
  }

  async update(client: AppClient): Promise<void> {
    const {
      id,
      secret,
      grants,
      redirectUris,
      accessTokenLifetime,
      refreshTokenLifetime,
      user,
    } = client;
    const username: string | undefined = "user" in client
      ? user?.username
      : (await this.getInternal(id))?.username;
    localStorage.setItem(
      `client:${id}`,
      JSON.stringify({
        id,
        secret,
        grants,
        redirectUris,
        accessTokenLifetime,
        refreshTokenLifetime,
        username,
      } as ClientInternal),
    );
  }

  delete(client: AppClient | string): Promise<boolean> {
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

  private toExternal(internal: ClientInternal): Promise<AppClient> {
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

  async get(clientId: string): Promise<AppClient | undefined> {
    const internal = await this.getInternal(clientId);
    return internal ? this.toExternal(internal) : undefined;
  }

  async getAuthenticated(
    clientId: string,
    clientSecret?: string,
  ): Promise<AppClient | undefined> {
    const internal = await this.getInternal(clientId);
    let client: AppClient | undefined = undefined;
    if (internal && clientSecret === internal.secret) {
      client = await this.toExternal(internal);
    }
    return client;
  }

  async getUser(client: AppClient | string): Promise<AppUser | undefined> {
    const clientId = typeof client === "string" ? client : client.id;
    const internal = await this.getInternal(clientId);
    return internal?.username
      ? await this.userService.get(internal.username)
      : undefined;
  }
}
