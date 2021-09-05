import { assertThrowsAsync, test, TestSuite } from "../test_deps.ts";
import { ServerError } from "../errors.ts";
import { client, ClientService } from "./test_services.ts";

const clientService = new ClientService();

const clientServiceTests: TestSuite<void> = new TestSuite({
  name: "ClientService",
});

test(clientServiceTests, "getUser", async () => {
  await assertThrowsAsync(
    () => clientService.getUser(client),
    ServerError,
    "clientService.getUser not implemented",
  );
});
