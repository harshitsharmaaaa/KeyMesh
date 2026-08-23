import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@keymesh/sdk', '@keymesh/protocol', '@keymesh/types'],
};

export default nextConfig;
