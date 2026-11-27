# APIShield — Paid tier

## Why a paid tier exists here

APIShield is deployed in front of production APIs. Teams running it in
production have a concrete need for support, managed rule updates, and a
hosted view of gateway events. That operational need is what the paid tier
serves.

## Free (this repository, MIT)

- Full gateway: BOLA/IDOR heuristics, JWT checks, auth-abuse detection,
  sensitive-data exposure scanning, security-header auditing
- Monitor and enforce modes, JSON event log, CLI report and demo
- Zero runtime dependencies, self-hosted

Nothing in the free gateway is disabled or degraded by the paid tier. The
`APISHIELD_PRO` environment flag (see `src/apishield/pro.py`) only records
explicit operator opt-in for paid integrations; it defaults to off and does
not change free behaviour.

## Paid (services around the gateway)

- Hosted event dashboard for gateway events (scoped web use-case: viewing
  and triaging recorded events across deployments)
- Managed rule updates and tuning help for a specific API surface
- Deployment review and priority support

These are roadmap/service items, delivered per deployment. No hosted
dashboard is bundled in this repository today.

## Payment reference

Paid arrangements are confirmed individually before any payment. Existing
payment references:

- NOWPayments $5 payment link (iid=4381731355)
- GitHub Sponsors: https://github.com/sponsors/gravion-ux

No public tier pricing is published here; scope and price are agreed in
writing for the specific deployment or support need.

Maintained by Priyanshu Kumar Thakur.
