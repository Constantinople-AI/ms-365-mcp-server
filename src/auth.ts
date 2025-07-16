import type { Configuration } from '@azure/msal-node';
import { PublicClientApplication } from '@azure/msal-node';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import logger from './logger.js';

class CryptoManager {
  private masterKey: Buffer;
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 12;
  private static readonly SALT_LENGTH = 16;
  private static readonly AUTH_TAG_LENGTH = 16;
  private static readonly KEY_LENGTH = 32;

  constructor(masterKeyHex: string) {
    if (!masterKeyHex) {
      throw new Error('A master encryption key is required. Please set MS365_MCP_MASTER_KEY.');
    }
    const masterKey = Buffer.from(masterKeyHex, 'hex');
    if (masterKey.length !== 32) {
      throw new Error('Master key must be a 32-byte (64-character hex) string.');
    }
    this.masterKey = masterKey;
  }

  private deriveKey(salt: Buffer, userId: string): Buffer {
    return crypto.hkdfSync(
      'sha256',
      this.masterKey,
      salt,
      `mcp-ms365-${userId}`,
      CryptoManager.KEY_LENGTH
    ) as Buffer;
  }

  encrypt(data: string, userId: string): string {
    const salt = crypto.randomBytes(CryptoManager.SALT_LENGTH);
    const key = this.deriveKey(salt, userId);
    const iv = crypto.randomBytes(CryptoManager.IV_LENGTH);

    const cipher = crypto.createCipheriv(CryptoManager.ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([salt, iv, authTag, encrypted]).toString('base64');
  }

  decrypt(encryptedPayload: string, userId: string): string {
    try {
      const dataBuffer = Buffer.from(encryptedPayload, 'base64');

      const salt = dataBuffer.subarray(0, CryptoManager.SALT_LENGTH);
      const iv = dataBuffer.subarray(
        CryptoManager.SALT_LENGTH,
        CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH
      );
      const authTag = dataBuffer.subarray(
        CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH,
        CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH + CryptoManager.AUTH_TAG_LENGTH
      );
      const encrypted = dataBuffer.subarray(
        CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH + CryptoManager.AUTH_TAG_LENGTH
      );

      const key = this.deriveKey(salt, userId);

      const decipher = crypto.createDecipheriv(CryptoManager.ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return decrypted.toString('utf8');
    } catch (error) {
      logger.error(`Decryption failed: ${(error as Error).message}. The master key may have changed or data is corrupt.`);
      throw new Error('Failed to decrypt token cache.');
    }
  }
}

const masterKey = process.env.MS365_MCP_MASTER_KEY;
if (!masterKey) {
  logger.warn(
    'MS365_MCP_MASTER_KEY environment variable not set. Token cache will not be encrypted. This is not recommended for production.'
  );
  logger.warn(
    `To generate a key, run: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
  );
}

const cryptoManager = masterKey ? new CryptoManager(masterKey) : null;

const endpoints = await import('./endpoints.json', {
  with: { type: 'json' },
});

const CACHE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.cache');

if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

const getCachePath = (userId: string) => {
  const hashedUserId = crypto.createHash('sha256').update(userId).digest('hex');
  return path.join(CACHE_DIR, `token-cache-${hashedUserId}.json.enc`);
};

const DEFAULT_CONFIG: Configuration = {
  auth: {
    clientId: process.env.MS365_MCP_CLIENT_ID || '084a3e9f-a9f4-43f7-89f9-d229cf97853e',
    authority: `https://login.microsoftonline.com/${process.env.MS365_MCP_TENANT_ID || 'common'}`,
  },
};

interface ScopeHierarchy {
  [key: string]: string[];
}

const SCOPE_HIERARCHY: ScopeHierarchy = {
  'Mail.ReadWrite': ['Mail.Read'],
  'Calendars.ReadWrite': ['Calendars.Read'],
  'Files.ReadWrite': ['Files.Read'],
  'Tasks.ReadWrite': ['Tasks.Read'],
  'Contacts.ReadWrite': ['Contacts.Read'],
};

function buildScopesFromEndpoints(): string[] {
  const scopesSet = new Set<string>();

  endpoints.default.forEach((endpoint) => {
    if (endpoint.scopes && Array.isArray(endpoint.scopes)) {
      endpoint.scopes.forEach((scope) => scopesSet.add(scope));
    }
  });

  Object.entries(SCOPE_HIERARCHY).forEach(([higherScope, lowerScopes]) => {
    if (lowerScopes.every((scope) => scopesSet.has(scope))) {
      lowerScopes.forEach((scope) => scopesSet.delete(scope));
      scopesSet.add(higherScope);
    }
  });

  return Array.from(scopesSet);
}

interface LoginTestResult {
  success: boolean;
  message: string;
  userData?: {
    displayName: string;
    userPrincipalName: string;
  };
}

interface UserTokenData {
  accessToken: string | null;
  tokenExpiry: number | null;
  msalApp: PublicClientApplication;
}
class AuthManager {
  private config: Configuration;
  private scopes: string[];
  private userTokens: Map<string, UserTokenData>;

  constructor(
    config: Configuration = DEFAULT_CONFIG,
    scopes: string[] = buildScopesFromEndpoints()
  ) {
    logger.info(`And scopes are ${scopes.join(', ')}`, scopes);
    this.config = config;
    this.scopes = scopes;
    this.userTokens = new Map();
  }

  private getUserTokenData(userId: string): UserTokenData {
    if (!this.userTokens.has(userId)) {
      logger.info(`Creating new token data for user: ${userId}`);
      this.userTokens.set(userId, {
        accessToken: null,
        tokenExpiry: null,
        msalApp: new PublicClientApplication(this.config),
      });
      // Load the cache for the new user instance
      this.loadTokenCache(userId).catch((error) => {
        logger.error(`Failed to lazy-load token cache for ${userId}: ${error}`);
      });
    }
    return this.userTokens.get(userId)!;
  }

  async loadTokenCache(userId: string): Promise<void> {
    try {
      const userTokenData = this.getUserTokenData(userId);
      const cachePath = getCachePath(userId);

      if (!fs.existsSync(cachePath)) {
        return;
      }

      const fileContent = fs.readFileSync(cachePath, 'utf8');

      if (cryptoManager) {
        const decryptedCache = cryptoManager.decrypt(fileContent, userId);
        userTokenData.msalApp.getTokenCache().deserialize(decryptedCache);
      } else {
        userTokenData.msalApp.getTokenCache().deserialize(fileContent);
      }
    } catch (error) {
      logger.error(`Error loading token cache for user ${userId}: ${(error as Error).message}`);
    }
  }

  async saveTokenCache(userId: string): Promise<void> {
    try {
      const userTokenData = this.getUserTokenData(userId);
      if (!userTokenData.msalApp.getTokenCache().hasChanged) {
        return;
      }
      const cacheData = userTokenData.msalApp.getTokenCache().serialize();
      const cachePath = getCachePath(userId);

      if (cryptoManager) {
        const encryptedCache = cryptoManager.encrypt(cacheData, userId);
        fs.writeFileSync(cachePath, encryptedCache);
      } else {
        fs.writeFileSync(cachePath, cacheData);
      }
    } catch (error) {
      logger.error(`Error saving token cache for user ${userId}: ${(error as Error).message}`);
    }
  }

  async getToken(userId: string, forceRefresh = false): Promise<string | null> {
    const userTokenData = this.getUserTokenData(userId);

    if (
      !forceRefresh &&
      userTokenData.accessToken &&
      userTokenData.tokenExpiry &&
      userTokenData.tokenExpiry > Date.now()
    ) {
      return userTokenData.accessToken;
    }

    const accounts = await userTokenData.msalApp.getTokenCache().getAllAccounts();

    if (accounts.length > 0) {
      const silentRequest = {
        account: accounts[0],
        scopes: this.scopes,
      };

      try {
        const response = await userTokenData.msalApp.acquireTokenSilent(silentRequest);
        userTokenData.accessToken = response.accessToken;
        userTokenData.tokenExpiry = response.expiresOn ? new Date(response.expiresOn).getTime() : null;
        await this.saveTokenCache(userId);
        return userTokenData.accessToken;
      } catch (error) {
        logger.info('Silent token acquisition failed, using device code flow');
      }
    }

    throw new Error('No valid token found');
  }

  async acquireTokenByDeviceCode(userId: string, hack?: (message: string) => void): Promise<string | null> {
    const userTokenData = this.getUserTokenData(userId);

    const deviceCodeRequest = {
      scopes: this.scopes,
      deviceCodeCallback: (response: { message: string }) => {
        const text = ['\n', response.message, '\n'].join('');
        if (hack) {
          hack(text + 'After login run the "verify login" command');
        } else {
          console.log(text);
        }
        logger.info('Device code login initiated');
      },
    };

    try {
      logger.info('Requesting device code...');
      logger.info(`Scopes are: ${this.scopes.join(', ')}`);
      const response = await userTokenData.msalApp.acquireTokenByDeviceCode(deviceCodeRequest);
      logger.info('Device code login successful');
      userTokenData.accessToken = response?.accessToken || null;
      userTokenData.tokenExpiry = response?.expiresOn ? new Date(response.expiresOn).getTime() : null;
      await this.saveTokenCache(userId);
      return userTokenData.accessToken;
    } catch (error) {
      logger.error(`Error in device code flow: ${(error as Error).message}`);
      throw error;
    }
  }

  async testLogin(userId: string): Promise<LoginTestResult> {
    try {
      logger.info(`Testing login for user: ${userId}...`);
      const token = await this.getToken(userId);

      if (!token) {
        logger.error('Login test failed - no token received');
        return {
          success: false,
          message: 'Login failed - no token received',
        };
      }

      logger.info('Token retrieved successfully, testing Graph API access...');

      try {
        const response = await fetch('https://graph.microsoft.com/v1.0/me', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const userData = await response.json();
          logger.info('Graph API user data fetch successful');
          return {
            success: true,
            message: 'Login successful',
            userData: {
              displayName: userData.displayName,
              userPrincipalName: userData.userPrincipalName,
            },
          };
        } else {
          const errorText = await response.text();
          logger.error(`Graph API user data fetch failed: ${response.status} - ${errorText}`);
          return {
            success: false,
            message: `Login successful but Graph API access failed: ${response.status}`,
          };
        }
      } catch (graphError) {
        logger.error(`Error fetching user data: ${(graphError as Error).message}`);
        return {
          success: false,
          message: `Login successful but Graph API access failed: ${(graphError as Error).message}`,
        };
      }
    } catch (error) {
      logger.error(`Login test failed: ${(error as Error).message}`);
      return {
        success: false,
        message: `Login failed: ${(error as Error).message}`,
      };
    }
  }

  async logout(userId: string): Promise<boolean> {
    try {
      const userTokenData = this.getUserTokenData(userId);
      const accounts = await userTokenData.msalApp.getTokenCache().getAllAccounts();
      for (const account of accounts) {
        await userTokenData.msalApp.getTokenCache().removeAccount(account);
      }
      userTokenData.accessToken = null;
      userTokenData.tokenExpiry = null;

      const cachePath = getCachePath(userId);
      if (fs.existsSync(cachePath)) {
        fs.unlinkSync(cachePath);
      }

      this.userTokens.delete(userId);

      return true;
    } catch (error) {
      logger.error(`Error during logout for user ${userId}: ${(error as Error).message}`);
      throw error;
    }
  }
}

export default AuthManager;
