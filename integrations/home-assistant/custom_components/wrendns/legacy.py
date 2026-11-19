"""Pre-rename spellings the integration still sends (ADR-1028, spec/10 T33.2).

A WrenDNS node that hasn't been upgraded yet reads `X-Telltale-Reason` and `X-Telltale-Client`, not
the `X-Wrendns-*` headers. The integration sends both for one release, so an agent token's changes
(which must give a reason) keep working against either version.
"""

from __future__ import annotations

LEGACY_REASON_HEADER = "X-Telltale-Reason"
LEGACY_CLIENT_HEADER = "X-Telltale-Client"
