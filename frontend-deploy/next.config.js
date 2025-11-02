/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    domains: [
      'kinjar-api.fly.dev',
      'localhost',
      'vercel-blob.com',
    ],
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**.public.blob.vercel-storage.com',
      },
      {
        protocol: 'https',
        hostname: 'kinjar-api.fly.dev',
      }
    ],
  },
  async rewrites() {
    return [
      // API proxy to backend
      {
        source: '/api/backend/:path*',
        destination: 'https://kinjar-api.fly.dev/:path*',
      }
    ]
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block'
          },
        ]
      }
    ]
  }
}

module.exports = nextConfig