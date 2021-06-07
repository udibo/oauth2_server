import { Client, ClientService, ClientServiceInterface } from "./client.ts";
import { test, TestSuite } from "../deps/udibo/test_suite/mod.ts";
import { assertThrowsAsync } from "../deps/std/testing/asserts.ts";
import { ServerError } from "../errors.ts";

const client: Client = {
  id: "1",
  grants: [],
};

export class ExampleClientService extends ClientService {
  get(_clientId: string): Promise<Client | undefined> {
    return Promise.resolve(client);
  }

  getAuthenticated(
    _clientId: string,
    _clientSecret?: string,
  ): Promise<Client | undefined> {
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
    ServerError,
    "clientService.getUser not implemented",
  );
});
