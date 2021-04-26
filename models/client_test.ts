import { Client, ClientService, ClientServiceInterface } from "./client.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import { assertThrowsAsync } from "../deps/std/testing/asserts.ts";

const client: Client = {
  id: "1",
  grants: [],
};

class ExampleClientService extends ClientService {
  get(_clientId: string, _clientSecret?: string): Promise<Client | void> {
    return Promise.resolve(client);
  }
}

const clientService: ClientServiceInterface = new ExampleClientService();

const clientServiceTests: TestSuite<void> = new TestSuite({
  name: "ClientService",
});

test(clientServiceTests, "getUser", async () => {
  await assertThrowsAsync(
    () => clientService.getUser(client),
    Error,
    "not implemented",
  );
});
