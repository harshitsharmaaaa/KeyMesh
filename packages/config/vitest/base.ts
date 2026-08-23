import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/*.test.ts', '**/*.test.tsx'],
    exclude: ['node_modules', 'dist', 'build', '.next'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules',
        'dist',
        'build',
        '.next',
        '**/*.test.ts',
        '**/*.test.tsx',
        '**/*.config.*',
        '**/mock*',
        '**/fixtures/**',
      ],
    },
  },
});
