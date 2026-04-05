import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_COOKIE_DEFAULT,
  KEYCLOAK_JOSE_SERVICE,
  KEYCLOAK_MULTITENANT_SERVICE,
  PolicyEnforcementMode,
} from '../constants';
import { META_ENFORCER_OPTIONS } from '../decorators/enforcer-options.decorator';
import { META_PUBLIC } from '../decorators/public.decorator';
import { META_RESOURCE } from '../decorators/resource.decorator';
import {
  ConditionalScopeFn,
  META_CONDITIONAL_SCOPES,
  META_SCOPES,
} from '../decorators/scopes.decorator';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import {
  extractRequestAndAttachCookie,
  resolveRealmConfig,
} from '../internal.util';
import { KeycloakJoseService } from '../services/keycloak-jose.service';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';

/**
 * Resource guard that enforces Keycloak UMA permissions.
 * Only controllers annotated with `@Resource` and methods with `@Scopes` are handled.
 */
@Injectable()
export class ResourceGuard implements CanActivate {
  private readonly logger = new Logger(ResourceGuard.name);

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
    @Inject(KEYCLOAK_JOSE_SERVICE)
    private readonly joseService: KeycloakJoseService,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private readonly multiTenant: KeycloakMultiTenantService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const resource = this.reflector.get<string>(
      META_RESOURCE,
      context.getClass(),
    );
    const explicitScopes =
      this.reflector.get<string[]>(META_SCOPES, context.getHandler()) ?? [];
    const conditionalScopes = this.reflector.get<ConditionalScopeFn>(
      META_CONDITIONAL_SCOPES,
      context.getHandler(),
    );
    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);
    // @EnforcerOptions is kept for backward compatibility but ignored in UMA flow
    this.reflector.getAllAndOverride(META_ENFORCER_OPTIONS, [
      context.getClass(),
      context.getHandler(),
    ]);

    const policyEnforcementMode =
      this.keycloakOpts.policyEnforcement || PolicyEnforcementMode.PERMISSIVE;
    const shouldAllow =
      policyEnforcementMode === PolicyEnforcementMode.PERMISSIVE;

    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie(context, cookieKey);

    if (!request) {
      return true;
    }

    if (!request.user && isPublic) {
      this.logger.verbose('Route has no user and is public, allowed');
      return true;
    }

    if (!resource) {
      if (shouldAllow) {
        this.logger.verbose(
          'No @Resource defined, allowed due to policy enforcement',
        );
      } else {
        this.logger.verbose(
          'No @Resource defined, denied due to policy enforcement',
        );
      }
      return shouldAllow;
    }

    const conditionalScopesResult =
      conditionalScopes != null
        ? conditionalScopes(request, request.user)
        : [];

    const scopes = [...explicitScopes, ...conditionalScopesResult];
    request.scopes = scopes;

    if (!scopes || scopes.length === 0) {
      if (shouldAllow) {
        this.logger.verbose(
          'No @Scopes defined, allowed due to policy enforcement',
        );
      } else {
        this.logger.verbose(
          'No @Scopes defined, denied due to policy enforcement',
        );
      }
      return shouldAllow;
    }

    this.logger.verbose(
      `Protecting resource [${resource}] with scopes: [${scopes}]`,
    );

    const user = request.user?.preferred_username ?? 'user';

    try {
      const realmConfig = await resolveRealmConfig(
        request,
        request.accessToken,
        this.keycloakOpts,
        this.multiTenant,
      );

      // Check each permission — all scopes must be granted
      const results = await Promise.all(
        scopes.map((scope) =>
          this.joseService.checkPermission(
            request.accessToken,
            realmConfig,
            `${resource}#${scope}`,
          ),
        ),
      );

      const isAllowed = results.every(Boolean);

      if (isAllowed) {
        this.logger.verbose(`Resource [${resource}] granted to [${user}]`);
      } else {
        this.logger.verbose(`Resource [${resource}] denied to [${user}]`);
      }

      return isAllowed;
    } catch (ex) {
      this.logger.warn(`Resource permission check error: ${ex.message}`);
      return shouldAllow;
    }
  }
}
