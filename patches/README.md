# VPP patch queue

Patches applied in lexical order on top of the pinned upstream VPP tag
before every release build. Format: `NNNN-short-name.patch`, applied
with `git apply`. Every patch carries a header block:

```
Problem: <one sentence, what breaks without this>
Upstream: <gerrit/issue link, or "not submitted" with why>
Upstream-Status: submitted | merged-in-<version> | local-only
```

Upstream-first: a fix that can go to fd.io goes to fd.io; local-only
needs a stated reason. A VPP version bump re-applies the queue: drop
what merged upstream, rebase what did not, and the bump PR lists the
disposition of every patch. A bump is not done until the queue is
clean and every plugin rebuilds.
