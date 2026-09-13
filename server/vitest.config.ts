import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    globals: true,
    fileParallelism: false, // Ensure tests don't step on each other in the memory db
  },
});
