#!/usr/bin/env python3
# Copyright 2026 Priya Pandey
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""whoami_token.py: Inspect and classify Google Cloud authentication tokens.

Answer one question: whose identity is this token carrying?

Usage Examples:
    # Pipe in an identity token from gcloud
    gcloud auth print-identity-token | python3 whoami_token.py

    # Query instance metadata from inside a GCP VM / Cloud Run container
    curl -s -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com" \
      | python3 whoami_token.py

    # Pass via argument or environment variable
    python3 whoami_token.py $TOKEN
    echo "$TOKEN" | python3 whoami_token.py

Note:
    This script DECODES the JWT payload for local auditing and debugging.
    It does not verify cryptographic signatures. Production services must
    validate signatures, issuers, audiences, and expiration using official libraries.
"""

import base64
from datetime import datetime, timezone
import json
import sys


def b64url_json(segment: str) -> dict:
    """Decode a Base64URL-encoded JSON string segment."""
    pad = "=" * (-len(segment) % 4)
    try:
        raw_json = base64.urlsafe_b64decode(segment + pad)
        return json.loads(raw_json)
    except Exception as e:
        sys.exit(f"Error decoding JWT segment: {e}")


def classify(claims: dict) -> str:
    """Classify the token principal across Human, Machine, and Agent identity kinds."""
    email = claims.get("email", "")
    iss = claims.get("iss", "")
    sub = claims.get("sub", "")

    # Google Cloud Agent Identity (SPIFFE / Workload Identity)
    if "agents.global" in sub or "system.id.goog" in iss or sub.startswith("spiffe://") or "reasoningEngines" in sub:
        return "AGENT IDENTITY (Isolated SPIFFE Principal / Vertex AI Agent Identity)"

    # Workload Identity Federation / STS
    if "sts.googleapis.com" in iss or sub.startswith("principal://"):
        return "FEDERATED WORKLOAD IDENTITY (Keyless external identity exchanged at runtime)"

    # Google Cloud Service Account (Machine Identity)
    # Catches .iam.gserviceaccount.com, .developer.gserviceaccount.com, and .appspot.gserviceaccount.com
    if email.endswith(".gserviceaccount.com"):
        return "SERVICE ACCOUNT (Machine Identity owned by your workload)"

    # Human Identity (Google Account / Workspace / Cloud Identity)
    if email:
        return "USER CREDENTIAL (Human Identity borrowed by the agent/session)"

    return "UNKNOWN / CUSTOM PRINCIPAL (Inspect 'iss' and 'sub')"


def main():
    # Read token from CLI argument or stdin
    if len(sys.argv) > 1 and sys.argv[1].strip():
        raw_token = sys.argv[1].strip()
    elif not sys.stdin.isatty():
        raw_token = sys.stdin.read().strip()
    else:
        print("Usage: gcloud auth print-identity-token | python3 whoami_token.py")
        print("   or: python3 whoami_token.py <JWT_TOKEN>")
        sys.exit(1)

    if not raw_token:
        sys.exit("Error: No token provided.")

    # Strip 'Bearer ' prefix if present
    if raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    segments = raw_token.split(".")
    if len(segments) != 3:
        sys.exit(
            f"Error: Not a valid JWT (expected 3 dot-separated segments, got {len(segments)})."
        )

    claims = b64url_json(segments[1])

    # Core claims
    identity = claims.get("email") or claims.get("sub") or "?"
    kind = classify(claims)

    print("\n" + "=" * 64)
    print(" 🔍 GOOGLE CLOUD TOKEN IDENTITY INSPECTOR")
    print("=" * 64)
    print(f"Identity : {identity}")
    print(f"Kind     : {kind}")
    print(f"Issuer   : {claims.get('iss', '?')}")
    print(f"Audience : {claims.get('aud', '?')}")
    if "sub" in claims and claims.get("sub") != identity:
        print(f"Subject  : {claims.get('sub')}")
    if "hd" in claims:
        print(f"Domain   : {claims['hd']} (Google Workspace / Cloud Identity)")
    if "azp" in claims and claims.get("azp") != claims.get("aud"):
        print(f"AuthParty: {claims['azp']}")

    # Expiry calculation
    exp = claims.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, timezone.utc)
        now_dt = datetime.now(timezone.utc)
        diff_mins = (exp_dt - now_dt).total_seconds() / 60

        if diff_mins < 0:
            status = f"EXPIRED ({abs(diff_mins):.0f} min ago)"
        else:
            status = f"valid ({diff_mins:.0f} min remaining)"
        print(f"Expires  : {exp_dt.isoformat()} [{status}]")
    print("=" * 64)

    # Security Warning for Human Tokens
    email = claims.get("email", "")
    if email and not email.endswith(".gserviceaccount.com"):
        print("\n⚠️  SECURITY WARNING:")
        print("    This token carries a HUMAN user identity.")
        print("    If an automated or background agent sends this token, every")
        print("    action it executes is indistinguishable from that human in")
        print("    all downstream Cloud Audit Logs.")
        print("    Recommendation: Give the agent its own dedicated Identity.")
        print("=" * 64 + "\n")


if __name__ == "__main__":
    main()
