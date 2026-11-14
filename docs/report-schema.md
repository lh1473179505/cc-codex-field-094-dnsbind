# report schema

`admit_chain` and `dnsbind admit` emit the same object.

```json
{
  "decision": "allow",
  "reason_codes": [],
  "qname": "www.example.com.",
  "qtype": "A",
  "zone": "example.com.",
  "kid": "z-example",
  "msgid": 41001,
  "final_name": "www.example.com.",
  "hops": ["www.example.com."],
  "notes": []
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is empty on allow. On deny it is a one-element list,
  the first matching code from `docs/admit-rules.md`.
- `qname`, `zone`, `final_name`, and `hops` use canonical names.
- `hops` is a list of canonical name strings, not the inspect hop objects.
- `notes` is an empty array for a real decision.
- `msgid` is the JSON integer from the message.

Inspect output is a different object and must stay field-compatible with
the scaffold: raw `qname`, `qtype`, `msgid`, `zone`, `kid`, and `hops`.
Each inspect hop is `{section, name, type, ttl, rdata}` using the strings
and numbers stored in the message, in wire order.
