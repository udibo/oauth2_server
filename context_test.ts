import {
  authorizeParameters,
  authorizeUrl,
  OAuth2AuthorizeRequest,
} from "./context.ts";
import { Client } from "./models/client.ts";
import { Scope } from "./models/scope.ts";
import { User } from "./models/user.ts";
import { challengeMethods, generateCodeVerifier } from "./pkce.ts";
import { fakeAuthorizeRequest } from "./test_context.ts";
import { assertEquals, test, TestSuite } from "./test_deps.ts";

const authorizeParametersTests = new TestSuite({
  name: "authorizeParameters",
});

test(authorizeParametersTests, "from search parameters", async () => {
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  assertEquals(await authorizeParameters(request), {
    responseType: "code",
    clientId: "1",
    redirectUri: "https://client.example.com/cb",
    state: "xyz",
    scope: "read write",
    challenge: challenge,
    challengeMethod: "S256",
  });
});

test(authorizeParametersTests, "from body", async () => {
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  const request = fakeAuthorizeRequest({
    "response_type": "code",
    "client_id": "1",
    "redirect_uri": "https://client.example.com/cb",
    "scope": "read write",
    "state": "xyz",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
  });
  request.url.search = "";
  assertEquals(await authorizeParameters(request), {
    responseType: "code",
    clientId: "1",
    redirectUri: "https://client.example.com/cb",
    state: "xyz",
    scope: "read write",
    challenge: challenge,
    challengeMethod: "S256",
  });
});

test(authorizeParametersTests, "from search parameters and body", async () => {
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  const request = fakeAuthorizeRequest({
    "response_type": "code",
    "redirect_uri": "https://client.example.com/cb",
    "state": "xyz",
    "code_challenge_method": "S256",
  });
  request.url.search = "";
  request.url.searchParams.set("client_id", "1");
  request.url.searchParams.set("scope", "read write");
  request.url.searchParams.set("code_challenge", challenge);
  assertEquals(await authorizeParameters(request), {
    responseType: "code",
    clientId: "1",
    redirectUri: "https://client.example.com/cb",
    state: "xyz",
    scope: "read write",
    challenge: challenge,
    challengeMethod: "S256",
  });
});

test(
  authorizeParametersTests,
  "prefer body over search parameters",
  async () => {
    const verifiers: string[] = Array(2).fill(null).map(() =>
      generateCodeVerifier()
    );
    const challenges: string[] = await Promise.all(
      Array(2).fill(null).map((_, i) => challengeMethods.S256(verifiers[i])),
    );
    const request = fakeAuthorizeRequest({
      "response_type": "code",
      "client_id": "1",
      "redirect_uri": "https://client.example.com/cb",
      "state": "xyz",
      "scope": "read write",
      "code_challenge": challenges[0],
      "code_challenge_method": "S256",
    });
    request.url.search = "";
    request.url.searchParams.set("response_type", "token");
    request.url.searchParams.set("client_id", "2");
    request.url.searchParams.set(
      "redirect_uri",
      "https://client2.example.com/cb",
    );
    request.url.searchParams.set("state", "abc");
    request.url.searchParams.set("scope", "read");
    request.url.searchParams.set("code_challenge", challenges[1]);
    request.url.searchParams.set("code_challenge_method", "plain");
    assertEquals(await authorizeParameters(request), {
      responseType: "code",
      clientId: "1",
      redirectUri: "https://client.example.com/cb",
      scope: "read write",
      state: "xyz",
      challenge: challenges[0],
      challengeMethod: "S256",
    });
  },
);

const authorizeUrlTests = new TestSuite({
  name: "authorizeUrl",
});

test(authorizeUrlTests, "without PKCE", async () => {
  const request = fakeAuthorizeRequest();
  const expectedUrl = new URL("https://example.com/authorize");
  expectedUrl.searchParams.set("response_type", "code");
  expectedUrl.searchParams.set("client_id", "1");
  expectedUrl.searchParams.set("redirect_uri", "https://client.example.com/cb");
  expectedUrl.searchParams.set("state", "xyz");
  expectedUrl.searchParams.set("scope", "read write");
  request.authorizeParameters = await authorizeParameters(request);

  assertEquals(
    authorizeUrl(request as OAuth2AuthorizeRequest<Client, User, Scope>),
    expectedUrl,
  );
});

test(authorizeUrlTests, "with PKCE", async () => {
  const verifier: string = generateCodeVerifier();
  const challenge: string = await challengeMethods.S256(verifier);
  const request = fakeAuthorizeRequest();
  request.url.searchParams.set("code_challenge", challenge);
  request.url.searchParams.set("code_challenge_method", "S256");
  const expectedUrl = new URL("https://example.com/authorize");
  expectedUrl.searchParams.set("response_type", "code");
  expectedUrl.searchParams.set("client_id", "1");
  expectedUrl.searchParams.set("redirect_uri", "https://client.example.com/cb");
  expectedUrl.searchParams.set("state", "xyz");
  expectedUrl.searchParams.set("scope", "read write");
  expectedUrl.searchParams.set("code_challenge", challenge);
  expectedUrl.searchParams.set("code_challenge_method", "S256");
  request.authorizeParameters = await authorizeParameters(request);

  assertEquals(
    authorizeUrl(request as OAuth2AuthorizeRequest<Client, User, Scope>),
    expectedUrl,
  );
});
