import { assertRejects, describe, it } from "../test_deps.ts";
import { ServerError } from "../errors.ts";
import { client, ClientService } from "./test_services.ts";

const clientService = new ClientService();

const clientServiceTests = describe("ClientService");

it(clientServiceTests, "getUser", async () => {
  await assertRejects(
    () => clientService.getUser(client),
    ServerError,
    "clientService.getUser not implemented",
  );
});
