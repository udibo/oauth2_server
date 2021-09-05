import { User } from "../deps.ts";

export interface AppUser extends User {
  username: string;
  email?: string;
}
