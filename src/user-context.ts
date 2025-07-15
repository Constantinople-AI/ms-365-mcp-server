import jwt from 'jsonwebtoken';
import logger from './logger.js';

// Custom error class for authentication failures
export class AuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

// Function to extract and verify user ID from JWT token
export function getUserId(owui_token: string): string {
  let token: string | undefined;
  
  try {
    // Use the owui_token parameter directly
    if (!owui_token || typeof owui_token !== 'string') {
      logger.warn('No token provided');
      throw new AuthenticationError('Missing token');
    }

    // Check if it's a Bearer token format
    if (owui_token.startsWith('Bearer ')) {
      // Extract the token by removing 'Bearer ' prefix
      token = owui_token.substring(7);
    } else {
      // Use the token directly if it's not in Bearer format
      token = owui_token;
    }
    
    // Get the JWT secret from environment variables
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      logger.error('JWT_SECRET environment variable not set');
      throw new AuthenticationError('Authentication service unavailable');
    }

    // Verify the JWT token
    const decoded = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] }) as any;
    
    // Extract the user ID from the token
    if (decoded && decoded.id) {
      logger.info(`Successfully extracted user ID: ${decoded.id}`);
      return decoded.id;
    } else {
      logger.warn('JWT token does not contain id field');
      throw new AuthenticationError('Invalid token payload');
    }
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    // Handle JWT verification errors
    if (error instanceof jwt.JsonWebTokenError) {
      logger.error(`JWT verification failed: ${error.message}`);
      throw new AuthenticationError(`Invalid or expired token`);
    }
    logger.error(`Error verifying JWT token: ${(error as Error).message}`);
    throw new AuthenticationError('Authentication failed');
  }
} 