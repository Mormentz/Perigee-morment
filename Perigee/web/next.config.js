/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@creit.tech/stellar-wallets-kit"],
  turbopack: {},

  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "stellar.creit.tech",
      },
    ],
  },
};

module.exports = nextConfig;
