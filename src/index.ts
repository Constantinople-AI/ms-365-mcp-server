#!/usr/bin/env node

import { parseArgs } from './cli.js';
import logger from './logger.js';
import AuthManager from './auth.js';
import MicrosoftGraphServer from './server.js';
import { version } from './version.js';

async function main(): Promise<void> {
  try {
    const args = parseArgs();

    const authManager = new AuthManager();

    const server = new MicrosoftGraphServer(authManager, args);
    await server.initialize(version);
    await server.start();
  } catch (error) {
    logger.error(`Startup error: ${error}`);
    process.exit(1);
  }
}

main();
