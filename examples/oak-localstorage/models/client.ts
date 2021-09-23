import { ClientInterface } from "../deps.ts";
import { User } from "./user.ts";

export interface Client extends ClientInterface {
  /** Secret used for authenticating a client. */
  secret?: string;
  /** A user that is controlled by the client. */
  user?: User;
}
