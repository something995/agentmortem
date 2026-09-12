# Security policy

## Reporting a vulnerability

AgentMortem takes security seriously. If you believe you've found a
vulnerability in AgentMortem itself (e.g. a way to crash the scanner on
malicious input, a way to force raw secrets into reports, or a path-traversal
in config discovery):

1. **Do not open a public issue or PR with a working exploit.**
2. Open a private vulnerability report on GitHub:
   <https://github.com/something995/New-idea/security/advisories/new>
3. We aim to acknowledge reports within 3 days and ship a fix in the next
   release when possible.

## Scope notes

- AgentMortem is a **read-only analyzer**: it does not execute content from
  the transcripts it scans. If you see a feature request that would make it
  execute, review, or otherwise act on scanned content, that is a security
  boundary — talk to us before building it.
- False positives are not vulnerabilities; please file them as regular
  issues so the rules can be tuned.
- The example fixtures under `examples/` contain **synthetic** credentials
  (e.g. AWS's documented example key `AKIAIOSFODNN7EXAMPLE`). Never commit
  real credentials to this repository.
