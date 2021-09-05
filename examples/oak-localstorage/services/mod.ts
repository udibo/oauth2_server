import { AuthorizationCodeService } from "./authorization_code.ts";
import { ClientService } from "./client.ts";
import { SessionService } from "./session.ts";
import { TokenService } from "./token.ts";
import { UserService } from "./user.ts";

export const userService = new UserService();
export const sessionService = new SessionService(userService);
export const clientService = new ClientService(userService);
export const authorizationCodeService = new AuthorizationCodeService(
  clientService,
  userService,
);
export const tokenService = new TokenService(clientService, userService);
