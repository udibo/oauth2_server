import { ServerError } from "../errors.ts";
import { User } from "./user.ts";

export interface Client {
  /** A unique identifier. */
  id: string;
  /** Grant types allowed for the client. */
  grants: string[];
  /** Redirect URIs allowed for the client. Required for the `authorization_code` grant type. */
  redirectUris?: string[];
  /** Client specific lifetime of access tokens in seconds. */
  accessTokenLifetime?: number;
  /** Client specific lifetime of refresh tokens in seconds. */
  refreshTokenLifetime?: number;
  // deno-lint-ignore no-explicit-any
  [key: string]: any;
}

export interface ClientServiceInterface {
  /** Retrieves a client. */
  get(clientId: string): Promise<Client | undefined>;
  /** Retrieves an authenticted client. */
  getAuthenticated(
    clientId: string,
    clientSecret?: string,
  ): Promise<Client | undefined>;
  /** Retrieves a user associated with a client. */
  getUser(client: Client): Promise<User | undefined>;
}

export abstract class ClientService implements ClientServiceInterface {
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
  getUser(_client: Client): Promise<User | undefined> {
    throw new ServerError("clientService.getUser not implemented");
  }
}
