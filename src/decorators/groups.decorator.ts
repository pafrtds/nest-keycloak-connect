import { SetMetadata } from '@nestjs/common';
import { GroupMatch } from '../constants';

export const META_GROUPS = 'groups';
export const META_GROUP_MATCHING_MODE = 'group-matching-mode';

/**
 * Requires the authenticated user to belong to one or more Keycloak groups.
 * Groups are matched against the `groups` claim in the JWT token.
 *
 * The `groups` claim must be mapped in Keycloak:
 * Client → Client scopes → Add mapper → Group Membership → Token Claim Name: groups
 *
 * @param groups - group paths to match (e.g. '/org/team-a' or 'team-a')
 */
export const Groups = (...groups: string[]) => SetMetadata(META_GROUPS, groups);

/**
 * Sets the matching mode for the @Groups decorator.
 * Defaults to {@link GroupMatch.ANY}.
 */
export const GroupMatchingMode = (mode: GroupMatch) =>
  SetMetadata(META_GROUP_MATCHING_MODE, mode);
