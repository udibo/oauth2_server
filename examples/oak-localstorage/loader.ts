import { clientService, userService } from "./services/mod.ts";

localStorage.clear();

userService.create({ username: "kyle", password: "qwerty" });
userService.create({ username: "john", password: "doe" });

clientService.put({
  id: "1000",
  secret: "1234",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: ["http://localhost:8000/cb"],
});

clientService.put({
  id: "1001",
  secret: "1234",
  grants: ["authorization_code", "client_credentials"],
  redirectUris: [
    // these are for manually testing the authorization_code grant with postman
    "https://oauth.pstmn.io/v1/callback",
    "https://oauth.pstmn.io/v1/browser-callback",
  ],
  user: await userService.get("john")!,
});
