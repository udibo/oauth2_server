# OAuth2 Server

[![version](https://img.shields.io/badge/release-v0.1.0-success)](https://deno.land/x/oauth2_server@v0.1.0)
[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/deno.land/x/oauth2_server@v0.1.0/mod.ts)
[![CI](https://github.com/udibo/oauth2_server/workflows/CI/badge.svg)](https://github.com/udibo/oauth2_server/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/udibo/oauth2_server/branch/main/graph/badge.svg?token=8Q7TSUFWUY)](https://codecov.io/gh/udibo/oauth2_server)
[![license](https://img.shields.io/github/license/udibo/oauth2_server)](https://github.com/udibo/oauth2_server/blob/master/LICENSE)

A standards compliant implementation of an OAuth 2.0 authorization server with
PKCE support.

This module was inspired by
[node-oauth2-server](https://github.com/oauthjs/node-oauth2-server).

## Features

- The OAuth 2.0 Authorization Framework
  [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) compliant
- The OAuth 2.0 Authorization Framework: Bearer Token Usage
  [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) compliant
- Proof Key for Code Exchange by OAuth Public Clients
  [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) compliant
- Follows best security practices from
  [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) and
  [OAuth 2.0 Security Best Current
  Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- Framework agnostic with officially supported adapter for
  [Oak](https://deno.land/x/oak)

## Installation

To include this module in a Deno project, you can import directly from the TS
files. This module is available in Deno's third part module registry but can
also be imported directly from GitHub using raw content URLs.

```ts
// Import from Deno's third party module registry
import { OAuth2Server } from "https://deno.land/x/oauth2_server@v0.1.0/mod.ts";
// Import from GitHub
import { OAuth2Server } "https://raw.githubusercontent.com/udibo/test_suite/v0.1.0/mod.ts";
```

## Usage

An example of how to use this module can be found
[here](https://deno.land/x/oauth2_server@v0.1.0/examples/oak-localstorage). I
wouldn't recommend using the example as is but it should give you an idea of how
to use it.

See
[deno docs](https://doc.deno.land/https/deno.land/x/oauth2_server@v0.1.0/mod.ts)
for more information.

### Grants

This module comes with the authorization code, client credentials, and refresh
token grant types. The authorization code grant supports PKCE but does not
require it.

An implementation of the resource owner password credentials grant can be found
[here](grants/password.ts) but is not included in mod.ts because the grant type
insecurely exposes the credentials of the resource owner to the client. See
[OAuth 2.0 Security Best Current
Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.4)
for more information.

The implicit grant was not implemented because it is vulnerable to access token
leakage and access token replay. You should use the authorization code grant
instead. See
[OAuth 2.0 Security Best Current
Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.2)
for more information.

#### Extension Grants

When implemented, extension grants will be added to the same folder as the other
grant types and added to this readme.

### Models

The [models folder](models) contains interfaces for objects used by this module.
You can extend the models how you want.

### Services

The [services folder](services) contains abstract classes and interfaces for
objects used by this module to get and store models.

The [oak-localstorage](examples/oak-localstorage) example shows how to use
localStorage for your services. The example includes some functions that are not
required by this module. Some of the functions in the example don't need to be
async since localStorage is syncronous but were made asyncronous to make it easy
to replace localStorage with something else that is asyncronous.

### Adapters

This module is framework agnostic. Adapters can be created to make this
compatible with any framework. It comes with an adapter for
[Oak](https://deno.land/x/oak).

If you would like to use this module with other frameworks, look at the oak
adapter for an example of how to implement an adapter.

The oak adapter can be found [here](adapters/oak.ts). A working example showing
how to use this module with the adapter can be found
[here](examples/oak-localstorage).
