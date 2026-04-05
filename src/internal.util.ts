import { ContextType, ExecutionContext } from '@nestjs/common';
import { KeycloakConnectConfig } from './interface/keycloak-connect-options.interface';
import { KeycloakMultiTenantService } from './services/keycloak-multitenant.service';
import { RealmConfig } from './services/keycloak-jose.service';
import { parseToken } from './util';

export const attachCookieToHeader = (request: any, cookieKey: string) => {
  if (request && request.cookies && request.cookies[cookieKey]) {
    request.headers.authorization = `Bearer ${request.cookies[cookieKey]}`;
  }
  return request;
};

type GqlContextType = 'graphql' | ContextType;

export const extractRequest = (context: ExecutionContext): [any, any] => {
  let request: any, response: any;

  if (context.getType() === 'http') {
    const httpContext = context.switchToHttp();
    request = httpContext.getRequest();
    response = httpContext.getResponse();
  } else if (context.getType<GqlContextType>() === 'graphql') {
    let gql: any;
    try {
      gql = require('@nestjs/graphql');
    } catch (er) {
      throw new Error('@nestjs/graphql is not installed, cannot proceed');
    }
    const gqlContext = gql.GqlExecutionContext.create(context).getContext();
    request = gqlContext.req;
    response = gqlContext.res;
  }

  return [request, response];
};

export const extractRequestAndAttachCookie = (
  context: ExecutionContext,
  cookieKey: string,
) => {
  const [tmpRequest, response] = extractRequest(context);
  const request = attachCookieToHeader(tmpRequest, cookieKey);
  return [request, response];
};

/**
 * Resolves the realm configuration for the current request.
 * Handles single-tenant, multi-tenant, and auto-realm-from-token scenarios.
 */
export const resolveRealmConfig = async (
  request: any,
  jwt: string,
  opts: KeycloakConnectConfig,
  multiTenant: KeycloakMultiTenantService,
): Promise<RealmConfig> => {
  const authServerUrl =
    opts.authServerUrl ||
    opts['auth-server-url'] ||
    opts.serverUrl ||
    opts['server-url'];

  if (opts.multiTenant?.realmResolver) {
    const resolved = opts.multiTenant.realmResolver(request);
    const realm = resolved instanceof Promise ? await resolved : resolved;

    const [secret, clientId, realmAuthServerUrl] = await Promise.all([
      multiTenant.resolveSecret(realm, request),
      multiTenant.resolveClientId(realm, request),
      multiTenant.resolveAuthServerUrl(realm, request),
    ]);

    return {
      authServerUrl: realmAuthServerUrl || authServerUrl,
      realm,
      clientId,
      secret,
    };
  }

  if (!opts.realm) {
    const payload = parseToken(jwt);
    const realm = (payload.iss as string).split('/realms/').pop();
    return {
      authServerUrl,
      realm,
      clientId: opts.clientId || opts['client-id'],
      secret: opts.secret,
    };
  }

  return {
    authServerUrl,
    realm: opts.realm,
    clientId: opts.clientId || opts['client-id'],
    secret: opts.secret,
  };
};
