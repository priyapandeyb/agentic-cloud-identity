# Agentic Cloud Identity on Google Cloud

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Google Cloud](https://img.shields.io/badge/Google%20Cloud-Agent%20Identity-4285F4?logo=googlecloud&logoColor=white)](https://cloud.google.com)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Companion repository for the Medium series **"Agentic Cloud Identity"** by Priya Pandey.

This repository provides code utilities, token inspection tools, and architecture blueprints for managing and auditing identity across Human, Machine (Service Account), and Agent Identity (SPIFFE Principal) kinds on Google Cloud and Agent Runtime.

---

> ### ⚠️ Security & Usage Disclaimer
> **Use at Your Own Risk:** This repository is an educational demonstration and architectural reference toolkit accompanying the Agentic Cloud Identity series, not an officially supported Google Cloud product or enterprise authorization framework.
>
> - **Local Diagnostic Only:** Tools like `whoami_token.py` decode unverified JWT payloads for local auditing, education, and debugging. They act as "flashlights" for developer inspection and are not production security authenticators. Production backend services must always cryptographically verify signatures, issuers, audiences, and expiration using official client libraries (such as `google-auth` or standard OIDC validators).
> - **Agent IAM & Credential Boundaries:** The agent identity and delegation patterns discussed in this repository should be thoroughly evaluated and tested in isolated sandbox/staging environments before applying IAM policies or automated credentials to production infrastructure. Never run unvetted autonomous agent harnesses with broad ambient access to production credentials, sensitive customer data, or internal networks.

---

## 🔍 `whoami_token.py` — Token Identity Inspector

A zero-dependency CLI tool that answers one fundamental question: **whose identity is this token carrying?**

It inspects and classifies any OpenID Connect (OIDC) or Google Cloud JWT identity token, identifying whether it belongs to:

- **A Human User Credential** (`user:email@example.com`)
- **A Machine Service Account** (`*.gserviceaccount.com`)
- **An Attested Agent Identity** (`principal://agents.global...` / SPIFFE)

```text
================================================================
 🔍 GOOGLE CLOUD TOKEN IDENTITY INSPECTOR
================================================================
Identity : billing-refund-agent@prod-support.iam.gserviceaccount.com
Kind     : SERVICE ACCOUNT (Machine Identity owned by your workload)
Issuer   : https://accounts.google.com
Audience : https://refund-tool-4f7q2.a.run.app
Expires  : 2026-08-31T18:45:00+00:00 [valid (59 min remaining)]
================================================================
```

---

### ⚡ Quickstart & Usage

#### 1. Inspect your active gcloud developer session
```bash
gcloud auth print-identity-token | python3 whoami_token.py
```

#### 2. Query Instance Metadata inside Cloud Run, GKE, or Compute Engine
```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com" \
  | python3 whoami_token.py
```

#### 3. Inspect a token from an environment variable or argument
```bash
python3 whoami_token.py $MY_IDENTITY_TOKEN
# or pipe directly
echo "$MY_IDENTITY_TOKEN" | python3 whoami_token.py
```

---

### ⚠️ Security Warning for Human Tokens in Agents

If an automated background agent runs using a human's credential, every downstream action appears under that person's name in Cloud Audit Logs. `whoami_token.py` automatically flags this:

```text
⚠️  SECURITY WARNING:
    This token carries a HUMAN user identity.
    If an automated or background agent sends this token, every
    action it executes is indistinguishable from that human in
    all downstream Cloud Audit Logs.
    Recommendation: Give the agent its own dedicated Identity.
```

---

## 📊 The Three Identity Kinds at a Glance

| Dimension | Human Identity | Machine Identity (Service Account) | Agent Identity |
| :--- | :--- | :--- | :--- |
| **Built For** | A person | Deterministic software | One specific AI agent instance |
| **Credential** | Password, MFA, session cookies | Short-lived OAuth tokens; keys possible | Auto-rotated X.509 certs, SPIFFE tokens |
| **Sharing** | Never permitted by policy | Common in practice across workloads | Isolated to the agent resource by default |
| **Impersonation** | Possible via domain-wide delegation | Grantable via Token Creator | Cannot be impersonated by other principals |
| **Authority Mode** | Direct user authority | Direct workload authority | Autonomous authority OR user consent |
| **Lifecycle** | HR offboarding | Manual IAM cleanup | Bound to the agent resource; deleted with it |

---

## 🧩 Identity Lives in the Harness, Not the Model

Large Language Models do not hold credentials or sign HTTP requests. The surrounding execution harness resolves credentials via Application Default Credentials (ADC) and performs tool execution:

```python
while not completed:
    # 1. The model proposes an action (intention)
    intention = model(context)

    # 2. The harness carries the credential and executes the call
    result = execute(intention.tool, intention.args)

    context.append(result)
```

- **Local workstation:** ADC resolves to your **Human User Credential**.
- **Cloud Run / GKE with attached SA:** ADC resolves to a **Machine Service Account**.
- **Vertex AI Agent Runtime:** ADC resolves to the agent's **SPIFFE Principal**.

---

## 📖 Medium Series Roadmap

This repository accompanies the 7-part Medium series:

- **Part 1:** Human, Machine, Agent: The Three Identity Kinds on Google Cloud
- **Part 2:** Identity in the Loop: Why Agent Security is a Harness Problem, Not an AI Problem
- **Part 3:** Auditing Your Fleet: Discovering What Your Agents Actually Run As Today (with Audit Scripts)
- **Part 4:** Provisioning Agent Identities Across Vertex AI, Cloud Run, and GKE
- **Part 5:** On-Behalf-Of Consent: Structuring Delegated Authority via Auth Manager
- **Part 6:** Authenticating Model Context Protocol (MCP) and Agent-to-Agent Hops
- **Part 7:** Fleet Governance: Identity Ceilings, Attribution, and Emergency Kill Switches

---

## 🔒 Note on Security

`whoami_token.py` decodes JWT payloads locally for inspection and debugging. It does not verify cryptographic signatures. Production services must validate signatures, issuers, audiences, and expiration using official libraries.

---

## 📄 License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

## 👩‍💻 Author

**Priya Pandey**  
GitHub: [@priyapandeyb](https://github.com/priyapandeyb)
