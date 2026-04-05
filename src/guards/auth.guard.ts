import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_COOKIE_DEFAULT,
  KEYCLOAK_JOSE_SERVICE,
  KEYCLOAK_MULTITENANT_SERVICE,
  KEYCLOAK_TOKEN_CACHE_SERVICE,
  TokenValidation,
} from '../constants';
import { META_PUBLIC } from '../decorators/public.decorator';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import {
  extractRequestAndAttachCookie,
  resolveRealmConfig,
} from '../internal.util';
import { KeycloakJoseService } from '../services/keycloak-jose.service';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';
import { KeycloakTokenCacheService } from '../services/keycloak-token-cache.service';

/**
 * An authentication guard. Will return a 401 unauthorized when it is unable to
 * verify the JWT token or Bearer header is missing.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
    @Inject(KEYCLOAK_JOSE_SERVICE)
    private readonly joseService: KeycloakJoseService,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private readonly multiTenant: KeycloakMultiTenantService,
    private readonly reflector: Reflector,
    @Optional()
    @Inject(KEYCLOAK_TOKEN_CACHE_SERVICE)
    private readonly tokenCache: KeycloakTokenCacheService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);

    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = extractRequestAndAttachCookie(context, cookieKey);

    if (!request) {
      return true;
    }

    const jwt = this.extractJwt(request.headers);
    const isJwtEmpty = jwt === null || jwt === undefined;

    if (!isPublic && isJwtEmpty) {
      this.logger.verbose('Empty jwt, unauthorized');
      throw new UnauthorizedException();
    }

    if (isPublic && isJwtEmpty) {
      return true;
    }

    this.logger.verbose('Validating jwt');

    const tokenValidation =
      this.keycloakOpts.tokenValidation || TokenValidation.ONLINE;
    const cacheOpts = this.keycloakOpts.tokenCache;

    // Check cache (only for ONLINE — OFFLINE and NONE are already fast)
    if (
      tokenValidation === TokenValidation.ONLINE &&
      this.tokenCache &&
      cacheOpts?.enabled
    ) {
      const cached = this.tokenCache.get(jwt);
      if (cached !== undefined) {
        if (!cached) {
          if (isPublic) return true;
          throw new UnauthorizedException();
        }
        request.user = this.joseService.decode(jwt);
        request.accessToken = jwt;
        return true;
      }
    }

    let payload: any = null;

    try {
      const realmConfig = await resolveRealmConfig(
        request,
        jwt,
        this.keycloakOpts,
        this.multiTenant,
      );
      payload = await this.joseService.verify(jwt, realmConfig, tokenValidation);
    } catch (ex) {
      this.logger.warn(`Token validation error: ${ex.message}`);
    }

    const isValidToken = payload !== null;

    // Store result in cache
    if (
      tokenValidation === TokenValidation.ONLINE &&
      this.tokenCache &&
      cacheOpts?.enabled &&
      payload?.exp
    ) {
      this.tokenCache.set(jwt, isValidToken, payload.exp, cacheOpts.maxTtl);
    }

    if (isValidToken) {
      request.user = payload;
      request.accessToken = jwt;
      this.logger.verbose(`User authenticated`, { user: payload });
      return true;
    }

    if (isPublic) {
      this.logger.warn('A jwt token was retrieved but failed validation.');
      return true;
    }

    throw new UnauthorizedException();
  }

  private extractJwt(headers: { [key: string]: string }): string | null {
    if (!headers?.authorization) {
      this.logger.verbose('No authorization header');
      return null;
    }

    const auth = headers.authorization.split(' ');

    if (auth[0].toLowerCase() !== 'bearer') {
      this.logger.verbose('No bearer header');
      return null;
    }

    return auth[1];
  }
}
