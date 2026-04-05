import { Provider } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { KEYCLOAK_CONNECT_OPTIONS } from './constants';
import {
  KeycloakConnectConfig,
  KeycloakConnectOptions,
  NestKeycloakConfig,
} from './interface/keycloak-connect-options.interface';

const parseConfig = (
  opts: KeycloakConnectOptions,
  config?: NestKeycloakConfig,
): KeycloakConnectConfig => {
  if (typeof opts === 'string') {
    const configPathRelative = path.join(__dirname, opts);
    const configPathRoot = path.join(process.cwd(), opts);

    let configPath: string;

    if (fs.existsSync(configPathRelative)) {
      configPath = configPathRelative;
    } else if (fs.existsSync(configPathRoot)) {
      configPath = configPathRoot;
    } else {
      throw new Error(
        `Cannot find file, looked in [ ${configPathRelative}, ${configPathRoot} ]`,
      );
    }

    const json = fs.readFileSync(configPath);
    const keycloakConfig = JSON.parse(json.toString());
    return Object.assign(keycloakConfig, config);
  }
  return opts;
};

export const createKeycloakConnectOptionProvider = (
  opts: KeycloakConnectOptions,
  config?: NestKeycloakConfig,
): Provider => ({
  provide: KEYCLOAK_CONNECT_OPTIONS,
  useValue: parseConfig(opts, config),
});
