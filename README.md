# heain-access

Standalone access-control service for the HEAIN Core Protocol ecosystem.
Issues and verifies `AccessGrant`s via pluggable `Verifier` implementations
(ID card, face, fingerprint, keycard, DCP/KDM key issuance).

Called directly by other Layer 3 modules (e.g. heain-mastering at DCP-build
time) — not registered into heain-job's data-type strategy/registry-pool.
