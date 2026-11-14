# dnsbind admit rules

A response is a JSON document. Admission recomputes an HMAC over one ASCII
canonical line, then applies zone-key, replay, TTL, bailiwick, CNAME, and
glue rules. The checks interact: a signature is over the records as
presented, and a later policy failure must still be reported as that
policy failure rather than by dropping records before signing.

## Message JSON

Required fields:

- `version`: must be the string `v1`
- `msgid`: JSON integer (not a string, not a boolean)
- `qname`: domain name
- `qtype`: RR type, compared in uppercase (`A`, `AAAA`, `CNAME`, `NS`, ...)
- `zone`: apex of the zone that owns this answer
- `kid`: key id
- `answers`, `authority`, `additional`: arrays of RR objects, possibly empty
- `sig`: base64url (no `=` padding) of HMAC-SHA256 over the canonical line

Each RR object has `name`, `type`, `ttl` (JSON integer, not a boolean), and
`rdata` (string).

Missing required fields, a non-integer msgid or ttl, a msgid store that is
not an object with a `msgids` object, an unknown `kid`, or a key whose
`status` is neither `active` nor `revoked` are load failures (exit 2).
Do not write the msgid store on load failure.

## Canonical names

Trim ASCII whitespace, lowercase, and require exactly one trailing dot.
Empty labels are rejected. `Www.Example.COM` and `Www.Example.COM.` both
become `www.example.com.`.

## Canonical RDATA

- `CNAME`, `NS`, `PTR`: canonical name
- `A`: four decimal octets, no leading zeros, values 0..255
- `AAAA`: trim and lowercase; do not re-expand `::`
- anything else: trimmed string

RDATA in this lab does not contain `,`, `/`, or `|`.

## Canonical line (normative)

ASCII, no spaces. RR tokens use wire order: every `answers` element in
array order, then every `authority` element, then every `additional`
element. Do not sort by owner, type, or name.

Section codes are exactly `an`, `ns`, and `ar`.

Each token is:

```
{section}/{canonical_name}/{TYPE}/{ttl}/{canonical_rdata}
```

Tokens are joined with `,` (no trailing comma). The line is:

```
v1|{msgid}|{canonical_qname}|{QTYPE}|{canonical_zone}|{kid}|{rrset}
```

`sig` is not part of the line. `QTYPE` and RR types are uppercase. `ttl`
and `msgid` are decimal without leading zeros. An empty RRset leaves the
final `|` in place with nothing after it.

HMAC-SHA256 key material is `keys[kid].secret`: decode hex when the secret
is non-empty, even-length, and only hex digits; otherwise use UTF-8 bytes.
Encode the raw 32-byte HMAC with base64url and strip `=` padding.
Alphabet is `A-Z`, `a-z`, `0-9`, `-`, `_`.

### Worked examples

`fixtures/cases/ok-a/message.json` signs this exact line:

```
v1|41001|www.example.com.|A|example.com.|z-example|an/www.example.com./A/300/192.0.2.10
```

Signature: `RD5np_tQ7aUo0AhG5U5XOcSRF406_iJAUf8oBBqia7c`

`fixtures/cases/ok-cname/message.json` stores mixed-case names. The line
uses canonical names, and the CNAME token stays before the A token
(wire order, not sorted). Sorting by owner would put `app.example.com.`
first and would not match:

```
v1|41002|www.example.com.|A|example.com.|z-example|an/www.example.com./CNAME/120/app.example.com.,an/app.example.com./A/300/192.0.2.20
```

Signature: `Lz2nKfFmQfDIGrs4PcUp4KN_iHw00yvrTa6lK3lIrNk`

## Keys

`fixtures/keys.json` is `{"keys": {"<kid>": {"secret", "status", "zone"}}}`.

Select the key by `kid`, not by scanning zones.

- Unknown kid → load failure (exit 2), not a deny reason.
- `status == "revoked"` → deny `kid_revoked`. The secret still verifies;
  do not report `bad_signature` and do not treat the kid as missing.
- Otherwise `canonical(key.zone)` must equal `canonical(message.zone)`.
  A raw string compare is wrong: `Example.COM.` matches `example.com.`.
  Mismatch → deny `zone_mismatch`.

## Policy

- `min_ttl`: every RR in answers, authority, and additional must have
  `ttl >= min_ttl`. Otherwise deny `ttl_floor`. Checking only the answer
  section is wrong.
- `max_cname_depth`: maximum number of CNAME records that may be followed.
- `allow_glue`: when false, an out-of-bailiwick NS referral cannot be
  satisfied with additional A/AAAA.

## Msgid store

JSON object `{"msgids": {"<decimal msgid>": true, ...}}`.

Object keys are decimal strings. `41007` as an int is not the same lookup
as the key `"41007"`. Presence of the key means replay, whatever the value
is.

- If `str(msgid)` is already a key → deny `replay`.
- On **allow only**, set `msgids[str(msgid)] = true`.
- Deny and load failure must not add a key.
- The CLI persists the store only after an allow, by writing a temporary
  file in the same directory and replacing the destination.

## Bailiwick

Apex `Z` contains name `N` only when the canonical names are equal, or
`N` ends with `.` + `Z` (label boundary). `Z` already includes its
trailing dot, so the suffix checked is `.example.com.` when the apex is
`example.com.`.

`www.notexample.com.` ends with the characters `example.com.` and is still
**not** in-bailiwick of `example.com.`.

Apply this only to the answer section:

- every answer owner name must be in-bailiwick of the message zone
- every answer RDATA whose type is `CNAME`, `NS`, or `PTR` must be
  in-bailiwick of the message zone

Do not apply it to authority NS targets. Those names are how a referral
points at another zone. Do not apply it to additional-section owners.

Failure reason: `out_of_bailiwick`.

## CNAME chase

Use this path when the message is not a referral (see Glue). Bailiwick
has already been applied to the answer RRs as stored.

1. `current` = canonical qname, `followed` = 0, `hops` = [`current`].
2. Let `links` be answer RRs whose canonical owner is `current` and whose
   type is `CNAME`, in wire order. If `links` is empty, go to step 5.
3. If `followed >= max_cname_depth`, deny `cname_depth`. Do not append the
   next target. `final_name` is `current`.
4. `target` = canonical RDATA of `links[0]`. If `target` is already in
   `hops`, deny `cname_loop` and keep `final_name` = `current`. Otherwise
   append `target`, set `current` = `target`, `followed` += 1, go to step 2.
5. If no answer RR has canonical owner `current` and type equal to the
   uppercase qtype, deny `nodata`. Otherwise allow. `final_name` is
   `current` in both cases.

A longer chain that would have matched qtype past the cap is still
`cname_depth`, not `nodata`. `fixtures/policy.json` sets
`max_cname_depth` to 2. `deny-cname-depth` has three CNAME records;
two may be followed and the third must not. The hops that fit are
`www.example.com.`, `a.example.com.`, `b.example.com.` and `final_name`
is `b.example.com.`.

## Glue

A message is a referral when `answers` is empty and `authority` contains
at least one `NS`. A referral is not NODATA just because the answer
section is empty. Do not chase CNAMEs on a referral.

Let `outside` be the canonical NS RDATA names from authority, first-seen
order, de-duplicated, that are **not** in-bailiwick of the zone.
In-bailiwick NS names do not need glue.

- `outside` empty: glue is not required.
- `outside` non-empty and `allow_glue` is false: deny `glue_forbidden`.
  Do not accept additional A/AAAA as a substitute.
- `outside` non-empty and `allow_glue` is true: every name in `outside`
  needs at least one additional RR of type `A` or `AAAA` whose canonical
  owner equals that NS name. Any other additional name does not count.
  If any outside NS name lacks such a record, deny `missing_glue`.

`deny-missing-glue` has NS `ns1.other.net.` and an additional A only for
`ns2.other.net.`. The reason is `missing_glue`, not `out_of_bailiwick`
and not `nodata`.

## Check order

First matching outcome wins. Do not keep collecting later reasons.

1. Load / shape failure (exit 2), including unknown kid.
2. `version` is not `v1` → `version_rejected`.
3. `kid_revoked`.
4. `zone_mismatch`.
5. `bad_signature`.
6. `replay`.
7. `ttl_floor`.
8. `out_of_bailiwick` on answer owners and answer name-typed RDATA.
9. Referral glue (`glue_forbidden` or `missing_glue`) or CNAME chase
   (`cname_depth`, `cname_loop`, `nodata`).

On any deny before chase or on a referral, `hops` is a one-element list
holding the canonical qname, and `final_name` is that same name.
`deny-cname-depth` is the exception described above: hops include every
name actually followed, and stop before the CNAME that would exceed the cap.

## Reason codes

Exact strings: `version_rejected`, `kid_revoked`, `zone_mismatch`,
`bad_signature`, `replay`, `ttl_floor`, `out_of_bailiwick`,
`cname_depth`, `cname_loop`, `nodata`, `missing_glue`, `glue_forbidden`.

`stub` is the scaffold placeholder. A finished admit must not return it.

## Fixture expectations

| case | decision | reason_codes |
| --- | --- | --- |
| ok-a | allow | [] |
| ok-cname | allow | [] |
| deny-bad-sig | deny | ["bad_signature"] |
| deny-bailiwick | deny | ["out_of_bailiwick"] |
| deny-cname-depth | deny | ["cname_depth"] |
| deny-revoked | deny | ["kid_revoked"] |
| deny-replay | deny | ["replay"] |
| deny-ttl | deny | ["ttl_floor"] |
| deny-missing-glue | deny | ["missing_glue"] |

`ok-cname` report names are canonical: qname `www.example.com.`, zone
`example.com.`, hops `["www.example.com.", "app.example.com."]`,
final_name `app.example.com.`. `inspect` still prints the mixed-case
strings stored in the file.

## Forbidden shortcuts

- Allowing a revoked kid because HMAC still verifies.
- Treating bailiwick as `name.endswith(apex)` without a label boundary.
- Applying answer bailiwick to authority NS targets.
- Treating an empty answer section plus NS authority as `nodata`.
- Treating any additional A as glue for a different NS name.
- Enforcing `min_ttl` only on answer RRs.
- Sorting RRset tokens before HMAC, or signing the raw mixed-case JSON.
- Looking up msgid with a JSON integer against string object keys.
- Inserting a msgid on a deny path, or inserting it before the decision
  is allow.
