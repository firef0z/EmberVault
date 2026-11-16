# EmberVault Portal

Standalone external portal service for public shares.
External end users access public links (`/share/<token>`) through this container without having direct access to EmberVault internal services or databases.

## Communication Requirements
- Outbound HTTP to Orchestrator: `TCP 8081` (`EMBERVAULT_ORCHESTRATOR_URL`)
- Inbound HTTP from end-users: `TCP 8083` (or reverse proxy port 443/80)

