# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
#
# Shared settings for the OpenID Foundation conformance-suite harness (sourced by the other scripts here).
# Everything the run writes (keys, certificates, logs, exports) goes to OIDF_WORK, outside the repository.

OIDF_WORK=${OIDF_WORK:-${TMPDIR:-/tmp}/helixiam-oidf-work}
OIDF_HOST=${OIDF_HOST:-helix-oidf.localtest.me}   # *.localtest.me resolves to 127.0.0.1 in public DNS
OIDF_TLS_PORT=${OIDF_TLS_PORT:-18943}             # the TLS proxy in front of HelixIAM (same port inside and outside Docker)
OIDF_HELIX_PORT=${OIDF_HELIX_PORT:-18080}         # HelixIAM's own plain-HTTP port on the host
OIDF_PG_PORT=${OIDF_PG_PORT:-15432}
OIDF_SUITE_PORT=${OIDF_SUITE_PORT:-18443}         # the suite's nginx (https), host side
OIDF_SUITE_IMAGE_TAG=${OIDF_SUITE_IMAGE_TAG:-latest}
OIDF_REALM=${OIDF_REALM:-oidf}
OIDF_HELIX_JAR=${OIDF_HELIX_JAR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/helix-iam-server/target/helix-iam-server-1.0.0-SNAPSHOT.jar}
export OIDF_WORK OIDF_HOST OIDF_TLS_PORT OIDF_HELIX_PORT OIDF_PG_PORT OIDF_SUITE_PORT OIDF_REALM
mkdir -p "$OIDF_WORK/pki"
