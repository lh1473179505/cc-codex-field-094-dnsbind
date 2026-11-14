# dnsbind

Offline lab for admitting a DNS answer chain.

`python -m dnsbind inspect --message <file>` prints qname, qtype, and
the chain hops in wire order (answers, then authority, then additional).

`python -m dnsbind admit` must decide allow or deny using
`docs/admit-rules.md`. Exit 0 allow, 1 deny, 2 load failure.

Standard library only. No Docker, no network.
