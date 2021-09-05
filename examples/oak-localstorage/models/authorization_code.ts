import { AuthorizationCode, Scope } from "../deps.ts";
import { AppClient } from "./client.ts";
import { AppUser } from "./user.ts";

export interface AppAuthorizationCode extends AuthorizationCode<Scope> {
  client: AppClient;
  user: AppUser;
}
