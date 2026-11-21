# Framework integrations

[Feature index](README.md)

## Browser Extension Guide

- [ ] Browser Extension Guide
  - [ ] Setup & Installations
  - [ ] Configure tsconfig
  - [ ] Create the client auth instance
  - [ ] Configure the manifest
  - [ ] Bundle your extension
  - [ ] Configure the server auth instance

## Cloudflare Guide

- [ ] Cloudflare Guide
  - [ ] Node.js Compatibility
  - [ ] Environment Variables
  - [ ] Client IP
  - [ ] Background Tasks
  - [ ] Database Connections
  - [ ] Cloudflare Workers KV

## SAML SSO with Okta

- [ ] SAML SSO with Okta

## Astro Integration

- [ ] Astro Integration
  - [ ] Mount the handler
  - [ ] Create a client
  - [ ] Auth Middleware
    - [ ] Astro Locals types
    - [ ] Middleware
    - [ ] Getting session on the server inside `.astro` file

## Convex Integration

- [ ] Convex Integration
  - [ ] Set environment variables
  - [ ] Add Convex auth config
  - [ ] Create the authentication Convex Component
    - [ ] Create the component definition
    - [ ] Register the component
    - [ ] Create a authentication instance
    - [ ] Generate the schema
    - [ ] Export adapter functions
  - [ ] Create the authentication client instance
  - [ ] Configure Next.js server helpers
  - [ ] Mount handlers
  - [ ] Set up Convex client provider
  - [ ] Usage
    - [ ] Create your functions
    - [ ] Using the authentication client
    - [ ] Using the Convex React hooks
    - [ ] Using the server helpers
    - [ ] SSR with server components

## Effect Integration

- [ ] Effect Integration
  - [ ] Mount the auth handler
  - [ ] Cross-origin requests
  - [ ] Protect application routes

## Electron Integration

- [ ] Electron Integration
  - [ ] Usage
    - [ ] Handling Authorization in the Browser
    - [ ] Handling Authentication in Electron
    - [ ] Sign Out
    - [ ] Subscribing to User Updates
    - [ ] Handling Errors
    - [ ] Manual Token Exchange
      - [ ] Front-end:
      - [ ] Electron:
    - [ ] User Image Proxy
    - [ ] Creating IPC bridges
  - [ ] Options
    - [ ] Server plugin
      - [ ] `codeExpiresIn?`
      - [ ] `redirectCookieExpiresIn?`
      - [ ] `cookiePrefix?`
      - [ ] `clientID?`
    - [ ] Proxy client
      - [ ] `protocol`
      - [ ] `callbackPath?`
      - [ ] `clientID?`
      - [ ] `cookiePrefix?`
    - [ ] Client plugin
      - [ ] `signInURL`
      - [ ] `protocol`
      - [ ] `callbackPath?`
      - [ ] `storage`
      - [ ] `storagePrefix?`
      - [ ] `cookiePrefix?`
      - [ ] `channelPrefix?`
      - [ ] `clientID?`
      - [ ] `sanitizeUser?`
      - [ ] `userImageProxy?`
      - [ ] `disableCache?`

## Elysia Integration

- [ ] Elysia Integration
  - [ ] Mount the handler
  - [ ] CORS
  - [ ] Macro

## Encore Integration

- [ ] Encore Integration
  - [ ] Mount the handler
  - [ ] CORS
  - [ ] Trusted Origins
  - [ ] Local Development
  - [ ] Protecting Endpoints
  - [ ] Learn More

## Expo Integration

- [ ] Expo Integration
  - [ ] Configure A authentication Backend
  - [ ] Add the Expo Plugin on Your Server
  - [ ] Initialize authentication Client
  - [ ] Scheme and Trusted Origins
    - [ ] Development Mode
  - [ ] Configure Metro Bundler
  - [ ] Usage
    - [ ] Authenticating Users
      - [ ] Social Sign-In
      - [ ] IdToken Sign-In
    - [ ] Session
    - [ ] Making Authenticated Requests to Your Server
      - [ ] Example: Usage With TRPC
  - [ ] Options
    - [ ] Expo Client
      - [ ] storage
      - [ ] scheme
      - [ ] disableCache
      - [ ] cookiePrefix
    - [ ] Expo Servers
      - [ ] disableOriginOverride

## Express Integration

- [ ] Express Integration
  - [ ] Mount the handler
  - [ ] Cors Configuration
  - [ ] Getting the User Session

## authentication Fastify Integration Guide

- [ ] authentication Fastify Integration Guide
  - [ ] Authentication Handler Setup
  - [ ] Trusted origins
  - [ ] Configuring CORS
  - [ ] Getting the User Session

## Hono Integration

- [ ] Hono Integration
  - [ ] Setup
    - [ ] Create a Hono App
    - [ ] Mount the Auth Handler
    - [ ] Additional Configuration
      - [ ] Cloudflare Workers
  - [ ] CORS
  - [ ] Middleware
  - [ ] Hono RPC

## Lynx Integration

- [ ] Lynx Integration
  - [ ] Create Client Instance
  - [ ] Usage
    - [ ] Authentication Methods
    - [ ] Hooks
      - [ ] useSession
    - [ ] Store Integration
    - [ ] Advanced Store Usage
  - [ ] Plugin Support
  - [ ] Error Handling
  - [ ] Features
    - [ ] Cross-Platform Support
    - [ ] Optimized Performance
    - [ ] Nanostores Integration
    - [ ] Selective Re-rendering
    - [ ] Full API Compatibility
    - [ ] TypeScript Support

## NestJS Integration

- [ ] NestJS Integration
  - [ ] Basic Setup
    - [ ] 1. Disable Body Parser
    - [ ] 2. Import AuthModule
    - [ ] 3. Route Protection
      - [ ] Global by default
  - [ ] Full Documentation

## Next.js integration

- [ ] Next.js integration
  - [ ] Create API Route
  - [ ] Create a client
  - [ ] RSC and Server actions
    - [ ] Example: Getting Session on a server action
    - [ ] Example: Getting Session on a RSC
    - [ ] Server Action Cookies
  - [ ] Auth Protection
    - [ ] Next.js 16+ (Proxy)
    - [ ] Next.js 15.2.0+ (Node.js Runtime Middleware)
    - [ ] Next.js 13-15.1.x (Edge Runtime Middleware)
      - [ ] For Next.js release `15.1.7` and below
      - [ ] For Next.js release `15.2.0` and above
      - [ ] Cookie-based checks (recommended for all versions)
    - [ ] How to handle auth checks in each page/route
  - [ ] Next.js 16 Compatibility
    - [ ] Migration Guide

## Nitro Integration

- [ ] Nitro Integration
  - [ ] Create a new Nitro Application
    - [ ] Prisma Adapter Setup
    - [ ] Update Prisma Schema
  - [ ] Mount The Handler
    - [ ] CORS
    - [ ] Auth Guard/Middleware
    - [ ] Example

## Nuxt Integration

- [ ] Nuxt Integration
  - [ ] Mount the handler
  - [ ] Create a client
  - [ ] Use the session
  - [ ] Protect pages
  - [ ] Protect server routes
  - [ ] Use the client during SSR
  - [ ] Reuse with a Nuxt layer
  - [ ] Resources & examples

## React Router v7 Integration

- [ ] React Router v7 Integration
  - [ ] Create auth instance
  - [ ] Create API Route
    - [ ] React Router v7
    - [ ] Remix v2 (Legacy)
  - [ ] Create a client
    - [ ] Sign Up
      - [ ] React Router v7
      - [ ] Remix v2 (Legacy)
    - [ ] Sign In
      - [ ] React Router v7
    - [ ] Remix v2 (Legacy)

## SolidStart Integration

- [ ] SolidStart Integration
  - [ ] Mount the handler

## SvelteKit Integration

- [ ] SvelteKit Integration
  - [ ] Mount the handler
  - [ ] Populate session data in the event (`event.locals`)
  - [ ] Server Action Cookies
  - [ ] Create a client

## TanStack Start Integration

- [ ] TanStack Start Integration
  - [ ] Usage
    - [ ] Mount the handler
    - [ ] Usage tips
    - [ ] Protecting Resources
      - [ ] Protecting Routes
      - [ ] Protecting Multiple Routes (Layout)
      - [ ] Protecting Server Functions

## Waku Integration

- [ ] Waku Integration
  - [ ] Mount the handler
  - [ ] Create a client
  - [ ] Collect cookies from server code
  - [ ] Write cookies to the response
  - [ ] Resolve the session before rendering
  - [ ] Read the session
  - [ ] Usage
    - [ ] Sign in from the client
    - [ ] Sign out from a server action
    - [ ] Redirect optimistically in middleware
    - [ ] Show the session on static pages
