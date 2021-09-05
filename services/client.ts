import { ServerError } from "../errors.ts";
import { Client } from "../models/client.ts";
import { User } from "../models/user.ts";

export interface ClientServiceInterface {
  /** Retrieves a client. */
  get(clientId: string): Promise<Client | undefined>;
  /** Retrieves an authenticted client. */
  getAuthenticated(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client | undefined>;
  /** Retrieves a user associated with a client. */
  getUser(client: Client | string): Promise<User | undefined>;
}

export abstract class AbstractClientService implements ClientServiceInterface {
  /** Retrieves a client. */
  abstract get(
    clientId: string,
  ): Promise<Client | undefined>;

  /** Retrieves an authenticated client. */
  abstract getAuthenticated(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client | undefined>;

  /** Retrieves a user associated with a client. */
  getUser(_client: Client | string): Promise<User | undefined> {
    throw new ServerError("clientService.getUser not implemented");
  }
}
