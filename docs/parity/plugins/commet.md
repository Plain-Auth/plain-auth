# Commet

[Feature index](../README.md)

## Commet

- [ ] Commet
  - [ ] Features
    - [ ] Automatic customer creation on signup
    - [ ] Customer portal for self-service billing management
    - [ ] Subscription management (get, cancel)
    - [ ] Feature access control (boolean, metered and seat-based)
    - [ ] Usage tracking for metered billing
    - [ ] Seat management for per-user pricing
    - [ ] Secure webhook handling with signature verification
  - [ ] Preparation
    - [ ] Configuring Auth Server
    - [ ] Configuring Auth Client
  - [ ] Configuration Options
    - [ ] Required Options
      - [ ] `client`
      - [ ] `use`
    - [ ] Optional Options
      - [ ] `createCustomerOnSignUp`
      - [ ] `getCustomerCreateParams`
    - [ ] Customers
  - [ ] Portal Plugin
    - [ ] Configuration
      - [ ] `returnUrl`
  - [ ] Subscriptions Plugin
  - [ ] Features Plugin
  - [ ] Usage Plugin
  - [ ] Seats Plugin
  - [ ] Webhooks Plugin
    - [ ] `onPayload`
    - [ ] `onSubscriptionCreated`
    - [ ] `onSubscriptionActivated`
    - [ ] `onSubscriptionCanceled`
    - [ ] `onSubscriptionUpdated`
    - [ ] `onSubscriptionPlanChanged`
    - [ ] `onPaymentReceived`
    - [ ] `onPaymentFailed`
    - [ ] `onInvoiceCreated`
