import { Inject, Injectable, Logger } from '@nestjs/common';
import { JWTPayload, createRemoteJWKSet, jwtVerify } from 'jose';
import { KEYCLOAK_CONNECT_OPTIONS, TokenValidation } from '../constants';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';

export interface RealmConfig {
  authServerUrl: string;
  realm: string;
  clientId: string;
  secret: string;
}

/**
 * Core service for JWT validation using Keycloak's JWKS endpoint via `jose`.
 * Replaces `keycloak-connect` for all token verification needs.
 */
@Injectable()
export class KeycloakJoseService {
  private readonly logger = new Logger(KeycloakJoseService.name);
  private readonly jwksClients = new Map<
    string,
    ReturnType<typeof createRemoteJWKSet>
  >();

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly opts: KeycloakConnectConfig,
  ) {}

  /**
   * Verifies a JWT token.
   *
   * - OFFLINE: verifies signature against JWKS only (fast, no per-request Keycloak call).
   * - ONLINE: verifies signature AND calls introspection endpoint (detects revoked tokens).
   * - NONE: decodes without any verification.
   *
   * Returns the JWT payload on success, or null on failure.
   */
  async verify(
    token: string,
    realmConfig: RealmConfig,
    validation: TokenValidation,
  ): Promise<JWTPayload | null> {
    if (validation === TokenValidation.NONE) {
      return this.decode(token);
    }

    try {
      const jwks = this.getJwksClient(realmConfig);
      const issuer = this.buildIssuer(realmConfig);

      const { payload } = await jwtVerify(token, jwks, { issuer });

      if (validation === TokenValidation.ONLINE) {
        const active = await this.introspect(token, realmConfig);
        if (!active) {
          this.logger.verbose('Token is inactive or revoked (introspection)');
          return null;
        }
      }

      return payload;
    } catch (ex) {
      this.logger.warn(`Token verification failed: ${ex.message}`);
      return null;
    }
  }

  /**
   * Checks a resource permission via Keycloak's UMA authorization endpoint.
   * @param permission Format: "resource" or "resource#scope"
   */
  async checkPermission(
    token: string,
    realmConfig: RealmConfig,
    permission: string,
  ): Promise<boolean> {
    const url = `${realmConfig.authServerUrl}/realms/${realmConfig.realm}/protocol/openid-connect/token`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token}`,
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
          audience: realmConfig.clientId,
          permission,
          response_mode: 'decision',
        }).toString(),
      });

      if (response.status === 403) {
        return false;
      }

      if (!response.ok) {
        this.logger.warn(
          `Permission check returned unexpected status ${response.status}`,
        );
        return false;
      }

      const data: any = await response.json();
      return data.result === true;
    } catch (ex) {
      this.logger.warn(`Permission check error: ${ex.message}`);
      return false;
    }
  }

  /**
   * Extracts the realm name from the token's `iss` claim.
   * Supports both /realms/{realm} and /auth/realms/{realm} formats.
   */
  resolveRealmFromToken(token: string): string {
    const payload = this.decode(token);

    if (!payload?.iss) {
      throw new Error('Token has no iss claim');
    }

    const parts = (payload.iss as string).split('/realms/');

    if (parts.length < 2) {
      throw new Error(`Cannot extract realm from iss: ${payload.iss}`);
    }

    return parts[1];
  }

  /**
   * Decodes the token payload without any verification.
   */
  decode(token: string): JWTPayload | null {
    try {
      const parts = token.split('.');
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    } catch {
      return null;
    }
  }

  private async introspect(
    token: string,
    realmConfig: RealmConfig,
  ): Promise<boolean> {
    const url = `${realmConfig.authServerUrl}/realms/${realmConfig.realm}/protocol/openid-connect/token/introspect`;
    const credentials = Buffer.from(
      `${realmConfig.clientId}:${realmConfig.secret}`,
    ).toString('base64');

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${credentials}`,
        },
        body: new URLSearchParams({ token }).toString(),
      });

      if (!response.ok) {
        return false;
      }

      const data: any = await response.json();
      return data.active === true;
    } catch (ex) {
      this.logger.warn(`Introspection error: ${ex.message}`);
      return false;
    }
  }

  private getJwksClient(realmConfig: RealmConfig) {
    const key = `${realmConfig.authServerUrl}/realms/${realmConfig.realm}`;

    if (!this.jwksClients.has(key)) {
      const jwksUri = `${key}/protocol/openid-connect/certs`;
      this.jwksClients.set(key, createRemoteJWKSet(new URL(jwksUri)));
      this.logger.verbose(
        `JWKS client created for realm: ${realmConfig.realm}`,
      );
    }

    return this.jwksClients.get(key);
  }

  private buildIssuer(realmConfig: RealmConfig): string {
    return `${realmConfig.authServerUrl}/realms/${realmConfig.realm}`;
  }
}
