import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const src = (pkg: string) =>
  fileURLToPath(new URL(`./packages/${pkg}/src/index.ts`, import.meta.url));

/**
 * Shared vitest config: workspace packages resolve to their TypeScript sources,
 * so tests never depend on a prior build.
 */
export const sharedConfig = defineConfig({
  resolve: {
    alias: {
      '@syncert/protocol': src('protocol'),
      '@syncert/crypto': src('crypto'),
      '@syncert/core': src('core'),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
