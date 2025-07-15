import type { Configuration } from '@azure/msal-node';
import { PublicClientApplication } from '@azure/msal-node';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import logger from './logger.js';

// Try to import keytar, but make it optional
let keytar: any = null;
try {
  keytar = await import('keytar');
  logger.info('Keytar loaded successfully - using secure credential storage');
} catch (error) {
  logger.warn(`Keytar failed to load: ${(error as Error).message}. Falling back to file-based storage.`);
}

const endpoints = await import('./endpoints.json', {
  with: { type: 'json' },
});

const SERVICE_NAME = 'ms-365-mcp-server';
const getTokenCacheAccount = (userId: string) => `msal-token-cache-${userId}`;
const FALLBACK_DIR = path.dirname(fileURLToPath(import.meta.url));
const getFallbackPath = (userId: string) => path.join(FALLBACK_DIR, '..', `.token-cache-${userId}.json`);

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
    }
    return this.userTokens.get(userId)!;
  }

  async loadTokenCache(userId: string): Promise<void> {
    try {
      const userTokenData = this.getUserTokenData(userId);
      let cacheData: string | undefined;

      // Try keytar first if available
      if (keytar) {
        try {
          const cachedData = await keytar.getPassword(SERVICE_NAME, getTokenCacheAccount(userId));
          if (cachedData) {
            cacheData = cachedData;
          }
        } catch (keytarError) {
          logger.warn(
            `Keychain access failed, falling back to file storage: ${(keytarError as Error).message}`
          );
        }
      }

      // Fall back to file storage if keytar not available or failed
      if (!cacheData) {
        const fallbackPath = getFallbackPath(userId);
        if (fs.existsSync(fallbackPath)) {
          cacheData = fs.readFileSync(fallbackPath, 'utf8');
        }
      }

      if (cacheData) {
        userTokenData.msalApp.getTokenCache().deserialize(cacheData);
      }
    } catch (error) {
      logger.error(`Error loading token cache for user ${userId}: ${(error as Error).message}`);
    }
  }

  async saveTokenCache(userId: string): Promise<void> {
    try {
      const userTokenData = this.getUserTokenData(userId);
      const cacheData = userTokenData.msalApp.getTokenCache().serialize();

      // Try keytar first if available
      if (keytar) {
        try {
          await keytar.setPassword(SERVICE_NAME, getTokenCacheAccount(userId), cacheData);
          return; // Success with keytar, no need to use file storage
        } catch (keytarError) {
          logger.warn(
            `Keychain save failed, falling back to file storage: ${(keytarError as Error).message}`
          );
        }
      }

      // Fall back to file storage if keytar not available or failed
      const fallbackPath = getFallbackPath(userId);
      fs.writeFileSync(fallbackPath, cacheData);
    } catch (error) {
      logger.error(`Error saving token cache for user ${userId}: ${(error as Error).message}`);
    }
  }

  async getToken(userId: string, forceRefresh = false): Promise<string | null> {
    const userTokenData = this.getUserTokenData(userId);
    
    if (userTokenData.accessToken && userTokenData.tokenExpiry && userTokenData.tokenExpiry > Date.now() && !forceRefresh) {
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

      // Clear stored credentials
      if (keytar) {
        try {
          await keytar.deletePassword(SERVICE_NAME, getTokenCacheAccount(userId));
        } catch (keytarError) {
          logger.warn(`Keychain deletion failed: ${(keytarError as Error).message}`);
        }
      }

      // Clean up file-based storage
      const fallbackPath = getFallbackPath(userId);
      if (fs.existsSync(fallbackPath)) {
        fs.unlinkSync(fallbackPath);
      }

      // Remove user data from memory
      this.userTokens.delete(userId);

      return true;
    } catch (error) {
      logger.error(`Error during logout for user ${userId}: ${(error as Error).message}`);
      throw error;
    }
  }
}

export default AuthManager;
