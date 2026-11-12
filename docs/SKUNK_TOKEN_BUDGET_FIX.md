# SKUNK local token allocation — 12 November 2026

The owner supplied actual VPS errors with `error_type: TokenBudgetExhausted`.
HackerAI GET /models returned HTTP200 and listed all three configured model IDs.
This identifies a local quota/accounting gate; it does not prove inference works.
The copied output omitted the budget totals, so allocation exhaustion and a
contract-violation block must still be distinguished from the compact summary.

The original bundle starts with allocation 2,000,000 under cap 50,000,000, with
historical used 744,368 and uncertain reservations 282,255 preserved. These are
initial artifact values, not a claim about the VPS's current counters. Further
usage, held reservations and independent-validation capacity reduce available
research headroom. Exporting ATLAS_TOKEN_ALLOCATION does not rewrite an existing
persistent ledger.

Current source provides:

```bash
skunk budget
skunk budget --add 10000000
```

The first command prints one short local summary. The explicit second command
adds ten million to the existing allocation, clamped at the existing cap. It
preserves usage, all pending/uncertain reservations, validation reserve, contract
status, the database and model/provider configuration. It acquires the CLI
controller lock and records an audit event. It starts no scan or inference.

Existing rc1/retry1 binaries do not have this new subcommand. The same reviewed
`atlas/skunk_budget.py` file can run standalone with their installed Python:

```bash
/path/to/skunk/runtime/bin/python3 -I /path/to/skunk_budget.py --add 10000000
```

Use the same Unix account, data-directory settings and existing installation.
Exit SKUNK with Ctrl+C before changing allocation. A `changed:true` result
confirms that the local allocation was increased. Start the original scope
command again to create a new run; previous completed runs remain preserved.
This does not buy HackerAI credits or raise monetary limits.

The helper refuses mutation if `contract_violation:true`, if the existing cap is
already allocated, if the proposed allocation cannot cover recorded usage and
holds, or if an active controller owns the runtime. Its short error includes
budget totals for review. It never clears a contract flag, resets consumption,
releases uncertain billing holds or starts a new ledger as a shortcut.

Build checks: source compilation and source/artifact digests. No application
tests, paid inference, target scans, or VPS execution were performed here.
