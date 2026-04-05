<div align="center">

# @pafrtds/nest-keycloak-connect

A Keycloak authentication and authorization module for NestJS, powered by [`jose`](https://github.com/panva/jose).

![NPM Version](https://img.shields.io/npm/v/@pafrtds/nest-keycloak-connect?style=for-the-badge)
![GitHub License](https://img.shields.io/github/license/pafrtds/nest-keycloak-connect?style=for-the-badge)

</div>

## Compatibility

| Package version | NestJS version |
| --------------- | -------------- |
| 1.x             | 10, **11**     |

> This package is fully compatible with **NestJS 11** and uses `jose` for JWT validation instead of the deprecated `keycloak-nodejs-connect`.

## Features

- Protect your resources using [Keycloak's Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/).
- Simply add `@Resource`, `@Scopes`, `@Roles`, or `@Groups` in your controllers and you're good to go.
- JWT validation via JWKS using [`jose`](https://github.com/panva/jose) — no deprecated dependencies.
- Online token validation cache to avoid hitting Keycloak on every request.
- Compatible with [Fastify](https://github.com/fastify/fastify) platform.
- **Compatible with NestJS 11.**

## Installation

```bash
npm install @pafrtds/nest-keycloak-connect --save
```

## Getting Started

### Module registration

```typescript
import {
  KeycloakConnectModule,
  PolicyEnforcementMode,
  TokenValidation,
} from '@pafrtds/nest-keycloak-connect';

KeycloakConnectModule.register({
  authServerUrl: 'http://localhost:8080',
  realm: 'master',
  clientId: 'my-nestjs-app',
  secret: 'secret',
  policyEnforcement: PolicyEnforcementMode.PERMISSIVE, // optional
  tokenValidation: TokenValidation.ONLINE,             // optional
});
```

Async registration:

```typescript
KeycloakConnectModule.registerAsync({
  useExisting: KeycloakConfigService,
  imports: [ConfigModule],
});
```

#### KeycloakConfigService

```typescript
import { Injectable } from '@nestjs/common';
import {
  KeycloakConnectOptions,
  KeycloakConnectOptionsFactory,
  PolicyEnforcementMode,
  TokenValidation,
} from '@pafrtds/nest-keycloak-connect';

@Injectable()
export class KeycloakConfigService implements KeycloakConnectOptionsFactory {
  createKeycloakConnectOptions(): KeycloakConnectOptions {
    return {
      authServerUrl: 'http://localhost:8080',
      realm: 'master',
      clientId: 'my-nestjs-app',
      secret: 'secret',
      policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
      tokenValidation: TokenValidation.ONLINE,
    };
  }
}
```

### Guards

Register globally via `APP_GUARD` (recommended order):

```typescript
providers: [
  { provide: APP_GUARD, useClass: AuthGuard },
  { provide: APP_GUARD, useClass: ResourceGuard },
  { provide: APP_GUARD, useClass: RoleGuard },
  { provide: APP_GUARD, useClass: GroupGuard },
];
```

Or scoped to a controller:

```typescript
@Controller('cats')
@UseGuards(AuthGuard, ResourceGuard)
export class CatsController {}
```

## Guards

### AuthGuard

Returns **401 Unauthorized** when the JWT is missing or invalid. Validates tokens against Keycloak's JWKS endpoint.

### ResourceGuard

Enforces resource-level permissions via Keycloak's UMA authorization endpoint. Requires `@Resource` + `@Scopes` on the controller/method.

### RoleGuard

Checks realm or client roles from the token claims. Requires `@Roles` on the method.

### GroupGuard

Checks group membership from the `groups` claim in the JWT. Requires `@Groups` on the method.

> To enable the `groups` claim: Keycloak → Client → Client scopes → Add mapper → **Group Membership** → Token Claim Name: `groups`

## Configuring controllers

```typescript
import {
  Resource, Roles, Scopes, Groups, Public,
  RoleMatchingMode, GroupMatchingMode, GroupMatch,
} from '@pafrtds/nest-keycloak-connect';

@Controller()
@Resource('product')
export class ProductController {

  @Get()
  @Public()
  async findAll() { ... }

  @Get(':id')
  @Scopes('view')
  async findOne() { ... }

  @Post()
  @Scopes('create')
  @Roles({ roles: ['manager', 'realm:admin'] })
  async create() { ... }

  @Delete(':id')
  @Scopes('delete')
  @Groups('/org/admins')
  async remove() { ... }

  @Put(':id')
  @Scopes('edit')
  @Groups('/org/admins', '/org/editors')
  @GroupMatchingMode(GroupMatch.ALL) // must belong to BOTH groups
  async update() { ... }
}
```

## Token Validation Cache

Caches online validation results to avoid calling Keycloak on every request. The TTL is derived from the token's `exp` claim.

> **Note:** revoked tokens may be accepted until the cache entry expires. Use a short `maxTtl` in environments requiring immediate revocation.

```typescript
KeycloakConnectModule.register({
  // ...
  tokenValidation: TokenValidation.ONLINE,
  tokenCache: {
    enabled: true,
    maxTtl: 30, // max 30 seconds, regardless of token lifetime
  },
});
```

To manually invalidate a token (e.g. after logout):

```typescript
constructor(private readonly tokenCache: KeycloakTokenCacheService) {}

async logout(accessToken: string) {
  this.tokenCache.invalidate(accessToken);
}
```

## Decorators

| Decorator            | Description                                                               |
| -------------------- | ------------------------------------------------------------------------- |
| `@KeycloakUser`      | Retrieves the current Keycloak user from the request.                     |
| `@AccessToken`       | Retrieves the raw access token string from the request.                   |
| `@ResolvedScopes`    | Retrieves the resolved scopes (used with `@ConditionalScopes`).           |
| `@EnforcerOptions`   | Keycloak enforcer options for `ResourceGuard`.                            |
| `@Public`            | Allows unauthenticated access to the route.                               |
| `@Resource`          | Keycloak resource name (used with `ResourceGuard`).                       |
| `@Scopes`            | Required scopes on a resource (used with `ResourceGuard`).                |
| `@ConditionalScopes` | Dynamic scopes resolved at request time.                                  |
| `@Roles`             | Required realm or client roles (used with `RoleGuard`).                   |
| `@RoleMatchingMode`  | Sets `RoleMatch.ANY` (default) or `RoleMatch.ALL` for `@Roles`.           |
| `@Groups`            | Required Keycloak group membership (used with `GroupGuard`).              |
| `@GroupMatchingMode` | Sets `GroupMatch.ANY` (default) or `GroupMatch.ALL` for `@Groups`.        |

## Token Validation Modes

| Mode      | Description                                                                                  |
| --------- | -------------------------------------------------------------------------------------------- |
| `ONLINE`  | Verifies JWT signature via JWKS **and** calls Keycloak's introspection endpoint per request. Detects revoked tokens. |
| `OFFLINE` | Verifies JWT signature via JWKS only. Fast, no per-request Keycloak calls. Does not detect revocation. |
| `NONE`    | Skips all validation. Use only in development or internal trusted networks.                  |

## Configuration options

| Option            | Description                                                                 | Default      |
| ----------------- | --------------------------------------------------------------------------- | ------------ |
| `authServerUrl`   | Keycloak server URL                                                         | required     |
| `realm`           | Realm name                                                                  | required     |
| `clientId`        | Client/Application ID                                                       | required     |
| `secret`          | Client secret                                                               | required     |
| `cookieKey`       | Cookie key for JWT extraction                                               | `KEYCLOAK_JWT` |
| `policyEnforcement` | `PERMISSIVE` or `ENFORCING` for `ResourceGuard`                           | `PERMISSIVE` |
| `tokenValidation` | `ONLINE`, `OFFLINE`, or `NONE`                                              | `ONLINE`     |
| `tokenCache`      | Cache config: `{ enabled, maxTtl? }`                                        | disabled     |
| `multiTenant`     | Multi-tenant options                                                        | —            |
| `roleMerge`       | `OVERRIDE` or `ALL` for `@Roles` merge strategy                             | `OVERRIDE`   |

## Multi-tenant configuration

```typescript
KeycloakConnectModule.register({
  authServerUrl: 'http://localhost:8080',
  clientId: 'nest-api',
  secret: 'fallback-secret',
  multiTenant: {
    realmResolver: (request) => request.get('host').split('.')[0],
    realmSecretResolver: (realm) => secretsMap[realm],
    realmClientIdResolver: (realm) => clientIdMap[realm],
    realmAuthServerUrlResolver: (realm) => authServerUrlMap[realm],
  },
});
```

## License

MIT — Copyright (c) 2020 John Joshua Ferrer, 2026 Lucas Paes
