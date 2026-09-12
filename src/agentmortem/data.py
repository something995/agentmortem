"""Shared static data used across AgentMortem scanners."""

from __future__ import annotations

import re

#: Hosts commonly used for data-exfiltration drop points, C2 callbacks, or
#: public paste services. A match is a *signal*, not proof of compromise.
EXFIL_HOSTS: tuple[str, ...] = (
    "webhook.site",
    "requestbin.com",
    "reqbin.com",
    "interact.sh",
    "oastify.com",
    "burpcollaborator",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "transfer.sh",
    "pipedream.net",
    "webhook.dingtalk.com",
    "hooks.zapier.com",
    "discordapp.com/api/webhooks",
    "discord.com/api/webhooks",
    "pastebin.com",
    "paste.rs",
    "hastebin.com",
    "0x0.st",
)


def _build_exfil_pattern() -> re.Pattern[str]:
    alts = [re.escape(host) for host in EXFIL_HOSTS]
    return re.compile(
        r"(?:https?://)?(?:[a-z0-9-]+\.)*(" + "|".join(alts) + r")",
        re.IGNORECASE,
    )


EXFIL_HOST_RE = _build_exfil_pattern()


def find_exfil_host(text: str) -> re.Match[str] | None:
    """Return the first exfil/suspicious host match in *text*, if any."""
    return EXFIL_HOST_RE.search(text)
