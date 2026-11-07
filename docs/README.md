# Product overview

## What this product does

This project is a just-in-time (JIT) SSH access engine. Instead of distributing each user's long-lived public key into target accounts' `~/.ssh/authorized_keys`, it issues short-lived OpenSSH user certificates signed by an SSH certificate authority (CA).

The intended default maximum certificate lifetime is 15 minutes. A user generates a temporary Ed25519 keypair on their client; the private key stays on that client, while the public key is sent to the engine. The engine signs the public key into a user certificate containing the requesting identity and permitted target account. The user then connects directly to the target over SSH using the key and certificate. The target's `sshd` trusts the CA public key and validates the certificate, principal, and validity period.

The result is centralized certificate issuance and simpler target trust configuration. It does not remove the need to authenticate users to the engine, authorize access to target accounts, protect the CA private key, or secure network communication.

## Why use SSH certificates?

An SSH certificate is a CA-signed statement about a public key. It is not a shared private credential: the client retains its private key, and target hosts need only trust the issuing CA. OpenSSH can enforce the certificate's validity period and principal during authentication.

For the target configuration described by this project, the operator installs the CA public key on each target and configures:

```text
TrustedUserCAKeys /etc/ssh/jit_ca.pub
```

The target does not need a copy of each client's public key in `authorized_keys`. Revoking a particular certificate before its expiry requires an additional mechanism such as a KRL; short expiration limits, but does not eliminate, the window of exposure.

## Comparison with Enterprise PAM

This is a comparison of the access path described here, not a feature-by-feature evaluation of CyberArk, BeyondTrust, or other PAM products. Enterprise PAM deployments are configurable and may offer capabilities beyond SSH key management.

| Area | This JIT SSH design | Common PAM deployment pattern |
|---|---|---|
| SSH credential | Client-held private key plus a short-lived CA-signed user certificate | May broker or retrieve credentials managed in a vault, including static SSH credentials |
| Lifetime | Issued certificate is capped at 15 minutes by the engine; OpenSSH checks its validity when authenticating | A vaulted credential may remain usable until rotation, expiry, or policy action; schedules vary |
| Target trust | One CA trust entry, `TrustedUserCAKeys /etc/ssh/jit_ca.pub`; no per-user key distribution is needed for this flow | Depending on configuration, public keys or managed accounts may need to be provisioned on target systems |
| SSH data path | Client connects directly to the target after certificate issuance | Some deployments route sessions through an inline session proxy or jump host; others may use different designs |
| Operational trade-off | Lightweight SSH-specific issuance and direct connectivity; the organization must build identity, authorization, audit, and CA operations around it | Broader PAM workflows and controls, with the operational and infrastructure footprint of the selected deployment |

Direct SSH avoids an inline session-proxy hop in this design, but it does not mean zero network latency. It still incurs normal client-to-target network latency, and certificate issuance requires a separate request to the engine. This project should not be considered a general replacement for enterprise PAM controls such as session recording, approval workflows, credential discovery, or rotation unless those capabilities are explicitly implemented and validated.

## Intended users and boundaries

The intended operators are teams that want short-lived SSH certificate-based access to managed Linux hosts and can operate an SSH CA securely.

Initial scope from the project requirements:

- A Go daemon that loads or creates an Ed25519 SSH CA and signs user certificates.
- An API endpoint for certificate requests.
- A CLI that creates a temporary Ed25519 keypair, requests a certificate, writes the resulting key and certificate to the user's SSH directory, and prints a direct SSH command.
- Target-side OpenSSH CA trust configuration and test coverage.

Not yet specified by the requirements, and therefore not to be assumed as implemented:

- How the caller authenticates to the API or how identities and target accounts are authorized.
- HTTPS termination and certificate management. The requirements mention both HTTP port 8080 and HTTPS signing; these must be reconciled before deployment outside a trusted local boundary.
- Approval policy, audit retention, rate limiting, certificate revocation, multi-tenant isolation, high availability, and CA rotation.
- Whether distribution is one executable with daemon/client subcommands or separate daemon and CLI executables built from one Go module.

Treat these as design and production-readiness decisions, not as capabilities already delivered.

## How the project will achieve the goal

Development is staged so each increment has a concrete test:

1. Establish the Go module, command entry points, and build/test tooling.
2. Implement CA lifecycle and SSH certificate signing, with unit tests verifying signatures and certificate fields.
3. Implement and test the request API, including malformed input and duration limits.
4. Implement the CLI's in-memory key generation, API call, restrictive local file writes, and SSH command output.
5. Verify the complete path against a disposable OpenSSH server configured to trust the CA, without client entries in `authorized_keys`.
6. Document operator setup and run the complete unit, integration, static-analysis, and build checks.

See the detailed, phase-by-phase acceptance commands in [the development TODO](../TODOList.md). The design and component interactions are described in [Architecture](./architecture.md).
