# Protocol fixtures

Fixtures in this directory are sanitized observations from authorized test
deployments or hand-written unit-test inputs. They must not contain production
credentials, live cookies, SIDs, CSRF tokens, access tokens, device identifiers,
private keys, user identifiers, or internal hostnames.

## Naming

- Use `<product>_<operation>_<case>.json` for decoded HTTP payloads.
- Use `<product>_<operation>_<case>.bin` for raw protocol bytes.
- Keep request and response fixtures in separate files.
- Record the protocol status and the date of capture in a neighboring `.meta.json`
  file without recording server identity.

## Redaction

- Replace secrets with stable placeholders such as `REDACTED_SID`.
- Replace hostnames with `vpn.example.test` and addresses with documentation ranges.
- Preserve field names, types, list ordering, status codes, and byte lengths.
- Never commit an unredacted capture for comparison or debugging.

## Evidence level

Each fixture metadata file must label the behavior as one of:

- `synthetic`: authored without a server capture.
- `observed`: captured from an authorized deployment and sanitized.
- `verified`: observed behavior confirmed by a repeatable interoperability test.

The internal tunnel codec must remain labeled `synthetic` until an authorized
interoperability test promotes it to `observed` or `verified`.
