import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import AuthManager from './auth.js';
import { getUserId, AuthenticationError } from './user-context.js';

export function registerAuthTools(server: McpServer, authManager: AuthManager): void {
  const owui_token = z.string().describe('Authentication token from OpenWebUI');
  server.tool(
    'login',
    'Authenticate with Microsoft 365 using device code flow',
    {
      force: z.boolean().describe('Force a new login even if already logged in'),
      owui_token: owui_token,
    },
    async ({ force, owui_token }) => {
      try {
        const userId = getUserId(owui_token);
        
        if (!force) {
          const loginStatus = await authManager.testLogin(userId);
          if (loginStatus.success) {
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    status: 'Already logged in',
                    ...loginStatus,
                  }),
                },
              ],
            };
          }
        }

        const text = await new Promise<string>((r) => {
          authManager.acquireTokenByDeviceCode(userId, r);
        });
        return {
          content: [
            {
              type: 'text',
              text,
            },
          ],
        };
      } catch (error) {
        if (error instanceof AuthenticationError) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'Authentication failed',
                  message: error.message,
                  statusCode: 401
                }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ error: `Authentication failed: ${(error as Error).message}` }),
            },
          ],
        };
      }
    }
  );

  server.tool(
    'logout', 
    'Log out and clear saved Microsoft 365 credentials',
    {
      owui_token: owui_token,
    }, 
    async ({ owui_token }) => {
      try {
        const userId = getUserId(owui_token);
        await authManager.logout(userId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ message: 'Logged out successfully' }),
            },
          ],
        };
      } catch (error) {
        if (error instanceof AuthenticationError) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'Authentication failed',
                  message: error.message,
                  statusCode: 401
                }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ error: 'Logout failed' }),
            },
          ],
        };
      }
    }
  );

  server.tool(
    'verify-login',
    'Verify current Microsoft 365 login status and test API access', 
    {
      owui_token: owui_token,
    },
    async ({ owui_token }) => {
      try {
        const userId = getUserId(owui_token);
        const testResult = await authManager.testLogin(userId);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(testResult),
            },
          ],
        };
      } catch (error) {
        if (error instanceof AuthenticationError) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'Authentication failed',
                  message: error.message,
                  statusCode: 401
                }),
              },
            ],
          };
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: 'Login verification failed',
                message: (error as Error).message,
              }),
            },
          ],
        };
      }
    }
  );
}
