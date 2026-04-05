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
  RoleMatch,
  RoleMerge,
} from '../constants';
import {
  META_ROLE_MATCHING_MODE,
  META_ROLES,
} from '../decorators/roles.decorator';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import { extractRequestAndAttachCookie } from '../internal.util';

/**
 * A role guard that checks realm or client roles from the JWT token claims.
 * Roles are set via `@Roles` decorator.
 *
 * Role format:
 *  - `"admin"` — checks client roles for the configured clientId, then realm roles as fallback.
 *  - `"realm:admin"` — checks realm roles explicitly.
 */
@Injectable()
export class RoleGuard implements CanActivate {
  private readonly logger = new Logger(RoleGuard.name);

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roleMerge = this.keycloakOpts.roleMerge ?? RoleMerge.OVERRIDE;
    const roles: string[] = [];

    const matchingMode = this.reflector.getAllAndOverride<RoleMatch>(
      META_ROLE_MATCHING_MODE,
      [context.getClass(), context.getHandler()],
    );

    if (roleMerge === RoleMerge.ALL) {
      const merged = this.reflector.getAllAndMerge<string[]>(META_ROLES, [
        context.getClass(),
        context.getHandler(),
      ]);
      if (merged) roles.push(...merged);
    } else if (roleMerge === RoleMerge.OVERRIDE) {
      const result = this.reflector.getAllAndOverride<string[]>(META_ROLES, [
        context.getClass(),
        context.getHandler(),
      ]);
      if (result) roles.push(...result);
    } else {
      throw new Error(`Unknown role merge strategy: ${roleMerge}`);
    }

    if (roles.length === 0) {
      return true;
    }

    const roleMatchingMode = matchingMode ?? RoleMatch.ANY;
    this.logger.verbose(`Using matching mode: ${roleMatchingMode}`, { roles });

    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie(context, cookieKey);

    if (!request) {
      return true;
    }

    if (!request.user) {
      this.logger.warn(
        'No user found in request, are you sure AuthGuard is first in the chain?',
      );
      return false;
    }

    const granted =
      roleMatchingMode === RoleMatch.ANY
        ? roles.some((r) => this.hasRole(request.user, r))
        : roles.every((r) => this.hasRole(request.user, r));

    if (granted) {
      this.logger.verbose('Resource granted due to role(s)');
    } else {
      this.logger.verbose('Resource denied due to mismatched role(s)');
    }

    return granted;
  }

  /**
   * Checks if the token payload contains the given role.
   *
   * - `realm:rolename` → checks realm_access.roles
   * - `rolename` → checks resource_access[clientId].roles, then realm_access.roles
   */
  private hasRole(user: any, role: string): boolean {
    const clientId =
      this.keycloakOpts.clientId || this.keycloakOpts['client-id'];

    if (role.startsWith('realm:')) {
      const realmRole = role.slice('realm:'.length);
      return user?.realm_access?.roles?.includes(realmRole) ?? false;
    }

    // Check client roles first
    if (clientId && user?.resource_access?.[clientId]?.roles?.includes(role)) {
      return true;
    }

    // Fall back to realm roles
    return user?.realm_access?.roles?.includes(role) ?? false;
  }
}
