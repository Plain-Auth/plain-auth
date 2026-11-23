# Framework integrations

[Feature index](README.md)

## Browser Extension Guide

- [ ] Browser Extension Guide
  - Setup & Installations — *not applicable: JavaScript only*
  - Configure tsconfig — *not applicable: JavaScript only*
  - Create the client auth instance — *not applicable: JavaScript only*
  - Configure the manifest — *not applicable: JavaScript only*
  - Bundle your extension — *not applicable: JavaScript only*
  - [ ] Configure the server auth instance

## Cloudflare Guide

- [ ] Cloudflare Guide
  - Node.js Compatibility — *not applicable: Cloudflare Workers runtime*
  - Environment Variables — *not applicable: Cloudflare Workers runtime*
  - [ ] Client IP
  - [ ] Background Tasks
  - Database Connections — *not applicable: Cloudflare Workers runtime*
  - Cloudflare Workers KV — *not applicable: Cloudflare Workers runtime*

## SAML SSO with Okta

- [ ] SAML SSO with Okta

## Astro Integration

- Astro Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - Create a client
  - Auth Middleware
    - Astro Locals types
    - Middleware
    - Getting session on the server inside `.astro` file

## Convex Integration

- Convex Integration — *not applicable: JavaScript framework*
  - Set environment variables
  - Add Convex auth config
  - Create the authentication Convex Component
    - Create the component definition
    - Register the component
    - Create a authentication instance
    - Generate the schema
    - Export adapter functions
  - Create the authentication client instance
  - Configure Next.js server helpers
  - Mount handlers
  - Set up Convex client provider
  - Usage
    - Create your functions
    - Using the authentication client
    - Using the Convex React hooks
    - Using the server helpers
    - SSR with server components

## Effect Integration

- Effect Integration — *not applicable: JavaScript framework*
  - Mount the auth handler
  - Cross-origin requests
  - Protect application routes

## Electron Integration

- [ ] Electron Integration
  - [ ] Usage
    - [ ] Handling Authorization in the Browser
    - Handling Authentication in Electron — *not applicable: JavaScript only*
    - Sign Out — *not applicable: JavaScript only*
    - Subscribing to User Updates — *not applicable: JavaScript only*
    - Handling Errors — *not applicable: JavaScript only*
    - Manual Token Exchange — *not applicable: JavaScript only*
      - Front-end:
      - Electron:
    - User Image Proxy — *not applicable: JavaScript only*
    - Creating IPC bridges — *not applicable: JavaScript only*
  - [ ] Options
    - [ ] Server plugin
      - [ ] `codeExpiresIn?`
      - [ ] `redirectCookieExpiresIn?`
      - [ ] `cookiePrefix?`
      - [ ] `clientID?`
    - Proxy client — *not applicable: JavaScript only*
      - `protocol`
      - `callbackPath?`
      - `clientID?`
      - `cookiePrefix?`
    - Client plugin — *not applicable: JavaScript only*
      - `signInURL`
      - `protocol`
      - `callbackPath?`
      - `storage`
      - `storagePrefix?`
      - `cookiePrefix?`
      - `channelPrefix?`
      - `clientID?`
      - `sanitizeUser?`
      - `userImageProxy?`
      - `disableCache?`

## Elysia Integration

- Elysia Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - CORS
  - Macro

## Encore Integration

- Encore Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - CORS
  - Trusted Origins
  - Local Development
  - Protecting Endpoints
  - Learn More

## Expo Integration

- [ ] Expo Integration
  - [ ] Configure A authentication Backend
  - [ ] Add the Expo Plugin on Your Server
  - Initialize authentication Client — *not applicable: JavaScript only*
  - [ ] Scheme and Trusted Origins
    - [ ] Development Mode
  - Configure Metro Bundler — *not applicable: JavaScript only*
  - [ ] Usage
    - [ ] Authenticating Users
      - [ ] Social Sign-In
      - [ ] IdToken Sign-In
    - Session — *not applicable: JavaScript only*
    - Making Authenticated Requests to Your Server — *not applicable: JavaScript only*
      - Example: Usage With TRPC
  - [ ] Options
    - Expo Client — *not applicable: JavaScript only*
      - storage
      - scheme
      - disableCache
      - cookiePrefix
    - [ ] Expo Servers
      - [ ] disableOriginOverride

## Express Integration

- Express Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - Cors Configuration
  - Getting the User Session

## authentication Fastify Integration Guide

- authentication Fastify Integration Guide — *not applicable: JavaScript framework*
  - Authentication Handler Setup
  - Trusted origins
  - Configuring CORS
  - Getting the User Session

## Hono Integration

- Hono Integration — *not applicable: JavaScript framework*
  - Setup
    - Create a Hono App
    - Mount the Auth Handler
    - Additional Configuration
      - Cloudflare Workers
  - CORS
  - Middleware
  - Hono RPC

## Lynx Integration

- Lynx Integration — *not applicable: JavaScript framework*
  - Create Client Instance
  - Usage
    - Authentication Methods
    - Hooks
      - useSession
    - Store Integration
    - Advanced Store Usage
  - Plugin Support
  - Error Handling
  - Features
    - Cross-Platform Support
    - Optimized Performance
    - Nanostores Integration
    - Selective Re-rendering
    - Full API Compatibility
    - TypeScript Support

## NestJS Integration

- NestJS Integration — *not applicable: JavaScript framework*
  - Basic Setup
    - 1. Disable Body Parser
    - 2. Import AuthModule
    - 3. Route Protection
      - Global by default
  - Full Documentation

## Next.js integration

- Next.js integration — *not applicable: JavaScript framework*
  - Create API Route
  - Create a client
  - RSC and Server actions
    - Example: Getting Session on a server action
    - Example: Getting Session on a RSC
    - Server Action Cookies
  - Auth Protection
    - Next.js 16+ (Proxy)
    - Next.js 15.2.0+ (Node.js Runtime Middleware)
    - Next.js 13-15.1.x (Edge Runtime Middleware)
      - For Next.js release `15.1.7` and below
      - For Next.js release `15.2.0` and above
      - Cookie-based checks (recommended for all versions)
    - How to handle auth checks in each page/route
  - Next.js 16 Compatibility
    - Migration Guide

## Nitro Integration

- Nitro Integration — *not applicable: JavaScript framework*
  - Create a new Nitro Application
    - Prisma Adapter Setup
    - Update Prisma Schema
  - Mount The Handler
    - CORS
    - Auth Guard/Middleware
    - Example

## Nuxt Integration

- Nuxt Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - Create a client
  - Use the session
  - Protect pages
  - Protect server routes
  - Use the client during SSR
  - Reuse with a Nuxt layer
  - Resources & examples

## React Router v7 Integration

- React Router v7 Integration — *not applicable: JavaScript framework*
  - Create auth instance
  - Create API Route
    - React Router v7
    - Remix v2 (Legacy)
  - Create a client
    - Sign Up
      - React Router v7
      - Remix v2 (Legacy)
    - Sign In
      - React Router v7
    - Remix v2 (Legacy)

## SolidStart Integration

- SolidStart Integration — *not applicable: JavaScript framework*
  - Mount the handler

## SvelteKit Integration

- SvelteKit Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - Populate session data in the event (`event.locals`)
  - Server Action Cookies
  - Create a client

## TanStack Start Integration

- TanStack Start Integration — *not applicable: JavaScript framework*
  - Usage
    - Mount the handler
    - Usage tips
    - Protecting Resources
      - Protecting Routes
      - Protecting Multiple Routes (Layout)
      - Protecting Server Functions

## Waku Integration

- Waku Integration — *not applicable: JavaScript framework*
  - Mount the handler
  - Create a client
  - Collect cookies from server code
  - Write cookies to the response
  - Resolve the session before rendering
  - Read the session
  - Usage
    - Sign in from the client
    - Sign out from a server action
    - Redirect optimistically in middleware
    - Show the session on static pages
