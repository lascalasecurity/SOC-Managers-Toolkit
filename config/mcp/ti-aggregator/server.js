#!/usr/bin/env node
// Shim to keep older mcporter configs happy. Delegate to the real ti-aggregator server.
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const real = path.resolve(process.cwd(), 'mcp/ti-aggregator/server.js');
await import(pathToFileURL(real));
