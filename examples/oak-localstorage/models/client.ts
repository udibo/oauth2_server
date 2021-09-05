import { Client } from "../deps.ts";
import { AppUser } from "./user.ts";

export interface AppClient extends Client {
  /** Secret used for authenticating a client. */
  secret: string;
  /** A user that is controlled by the client. */
  user?: AppUser;
}
