# OAuth2 Server Oak Adapter

This adapter makes OAuth2 Server compatible with the
[Oak](https://deno.land/x/oak) framework.

## Installation

To include this module in a Deno project, you can import directly from the TS
files. This module is available in Deno's third part module registry but can
also be imported directly from GitHub using raw content URLs.

There are 2 different main entry points for this module.

- [authorization_server.ts](authorization_server.ts)
- [resource_server.ts](resource_server.ts)

The ResourceServer provides methods for authenticating requests and verifying
the request has proper authorization. You should use this if your server is not
also acting as an authorization server.

```ts
// Import from Deno's third party module registry
import { OakResourceServer } from "https://deno.land/x/oauth2_server@0.6.1/adapters/oak/resource_server.ts";
// Import from GitHub
import { OakResourceServer } from "https://raw.githubusercontent.com/udibo/oauth2_server/0.6.1/adapters/oak/resource_server.ts";
```

The AuthorizationServer is an extension of the ResourceServer, adding methods
used by the authorize and token endpoints.

```ts
// Import from Deno's third party module registry
import { OakAuthorizationServer } from "https://deno.land/x/oauth2_server@0.6.1/adapters/oak/authorization_server.ts";
// Import from GitHub
import { OakAuthorizationServer } from "https://raw.githubusercontent.com/udibo/oauth2_server/0.6.1/adapters/oak/authorization_server.ts";
```

## Usage

An example of how to use this adapter module can be found
[here](examples/oak-localstorage). I wouldn't recommend using the example as is
but it should give you an idea of how to use this module.

See
[deno docs](https://doc.deno.land/https/deno.land/x/oauth2_server@0.6.1/adapters/oak/authorization_server.ts)
for more information.
