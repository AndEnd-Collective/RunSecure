/**
 * Simulates a build step — writes output to a dist/ directory.
 * Validates that the runner can write to the workspace (tmpfs).
 */
const fs = require('node:fs');
const path = require('node:path');

const distDir = path.join(__dirname, '..', 'dist');
fs.mkdirSync(distDir, { recursive: true });

const output = {
  name: 'runsecure-test-node',
  version: '1.0.0',
  builtAt: new Date().toISOString(),
  nodeVersion: process.version,
  platform: process.platform,
  arch: process.arch,
  user: process.env.USER || 'unknown',
  uid: process.getuid ? process.getuid() : 'N/A',
};

fs.writeFileSync(
  path.join(distDir, 'build-info.json'),
  JSON.stringify(output, null, 2)
);

console.log('Build complete:', JSON.stringify(output, null, 2));
