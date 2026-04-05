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
  GroupMatch,
} from '../constants';
import {
  META_GROUPS,
  META_GROUP_MATCHING_MODE,
} from '../decorators/groups.decorator';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import { extractRequestAndAttachCookie } from '../internal.util';

/**
 * Guard that validates Keycloak group membership.
 * Requires the `groups` claim to be present in the JWT token.
 *
 * To enable the groups claim, add a Group Membership mapper in Keycloak:
 * Client → Client scopes → Add mapper → Group Membership → Token Claim Name: groups
 */
@Injectable()
export class GroupGuard implements CanActivate {
  private readonly logger = new Logger(GroupGuard.name);

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private keycloakOpts: KeycloakConnectConfig,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredGroups = this.reflector.getAllAndOverride<string[]>(
      META_GROUPS,
      [context.getClass(), context.getHandler()],
    );

    if (!requiredGroups || requiredGroups.length === 0) {
      return true;
    }

    const matchingMode =
      this.reflector.getAllAndOverride<GroupMatch>(META_GROUP_MATCHING_MODE, [
        context.getClass(),
        context.getHandler(),
      ]) ?? GroupMatch.ANY;

    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie(context, cookieKey);

    // if is not an HTTP request ignore this guard
    if (!request) {
      return true;
    }

    if (!request.user) {
      this.logger.warn(
        'No user found in request, are you sure AuthGuard is first in the chain?',
      );
      return false;
    }

    const userGroups: string[] = request.user.groups ?? [];

    if (userGroups.length === 0) {
      this.logger.warn(
        `User has no groups claim. Make sure the Group Membership mapper is configured in Keycloak.`,
      );
      return false;
    }

    // Normalize: Keycloak groups can come as '/group' or 'group'
    const normalize = (g: string) => g.replace(/^\//, '').toLowerCase();
    const normalizedUserGroups = userGroups.map(normalize);

    const granted =
      matchingMode === GroupMatch.ANY
        ? requiredGroups.some((g) => normalizedUserGroups.includes(normalize(g)))
        : requiredGroups.every((g) => normalizedUserGroups.includes(normalize(g)));

    if (granted) {
      this.logger.verbose(`Group access granted`);
    } else {
      this.logger.verbose(
        `Group access denied. Required: [${requiredGroups}], user has: [${userGroups}]`,
      );
    }

    return granted;
  }
}
