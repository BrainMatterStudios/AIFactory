# Model tiering — which role runs on which model, and how to decide

A persona team spends most of a factory's budget inside agents nobody watches
run. Tiering is the largest cost lever you have that does not touch quality — and
the fastest way to quietly break the quality gate, if you pull it in the wrong
place.

This is the policy the factory ships with, why each part of it is there, and how
to re-derive it for your own repo instead of inheriting ours.

---

## The three tiers

Tiers are abstract (`opus` / `sonnet` / `haiku`) and mapped to concrete vendor
model ids by your manifest (`runner.models`). Nothing in the core names a vendor.

| Tier | What belongs here |
|---|---|
| **opus** | Hard reasoning and judgment, and **every judge**. This is the *frontier floor*. |
| **sonnet** | Standard work, **all review agents**, and **thoroughness-critical coding** — parsers, input/format handling, adapters, edge-case-heavy logic. |
| **haiku** | Mechanical and clean-algorithmic coding, code reading and exploration, structured text (changelogs, docs, release notes). |

---

## The frontier floor — the part that is not a preference

Judges, the security veto, and whoever owns the T2 plan gate stay on the top
tier. Always.

The reasoning is asymmetric, which is what makes it a rule rather than a
trade-off. When a *worker* runs on too cheap a model, the work is visibly worse
and the judge catches it — the system self-corrects. When a **judge** runs on too
cheap a model, nothing looks wrong at all. It returns PASS. Work that should have
been stopped ships, and the only evidence is a defect in production weeks later
that nobody traces back to a routing decision. A cheap gate does not fail loudly;
it fails silently and takes the rest of the system's credibility with it.

So the floor is enforced in code, not documented as an intention:

```python
from software_factory.core.personas import assert_tier_policy, load_catalog
assert assert_tier_policy(load_catalog()) == []
```

`factory doctor` runs this, and `tests/test_tiers.py` asserts it in CI. Marking a
role `tier_lock: floor` in `catalog.yaml` is what puts it under the rule; nothing
about editing that file can lower it afterwards without the check going red.

**Why it is in code at all:** the catalog is deliberately editable data — adopters
add personas, domain packs override them. That is the right design for a roster
and the wrong design for a safety property. The moment a cost-reduction pass
sweeps the catalog looking for `opus`, the gate is exactly what it will find
first, and it is the one entry that must not move.

---

## Thoroughness-critical roles — what benchmarking actually found

The interesting result is not "cheaper models are worse." It is *how* they are
worse.

On mechanical and clean-algorithmic coding, code reading, and structured text,
the cheap tier came back at quality parity with the standard tier — same
correctness, a fraction of the cost. That class should move down, and in this
catalog it has.

On input- and format-heavy work — parsers, adapters, anything with a wide input
surface — the cheap tier did not produce visibly worse code. It produced code
that **silently under-covered**: it handled the input shapes named in the prompt
and quietly dropped the ones that were not, returning empty rather than failing.
That failure mode is nearly invisible in a diff review. The code reads correctly.
The tests you were given pass. What is missing is a branch nobody asked about.

Roles whose failure mode is *incompleteness rather than wrongness* therefore stay
at or above the standard tier, marked `tier_lock: thorough`. In the shipped
catalog that is `test-author` (coverage completeness), `api-contract-designer`
(backward-compatibility analysis), and `data-modeler` (migration correctness).
Your domain pack should mark its own parser and adapter specialists the same way.

---

## Reused built-ins — pin them, always

Built-in agents (`code-reviewer`, `Explore`, `Plan`, …) carry no catalog entry.
Spawn one without an explicit model and it inherits whatever your host defaults
to.

That is not a theoretical concern. It is how a gate-adjacent reviewer ends up
running on the cheapest available model with nobody having decided that — the
kind of gap that is invisible until you go looking for it, because there is no
line of code anywhere stating the wrong thing. There is just an absent argument.

The catalog's `builtins:` block records the required pin; ask for it rather than
reading the map:

```python
from software_factory.core.personas import builtin_model
builtin_model("code-reviewer")            # 'sonnet' — pinned
builtin_model("Plan", tier="T2")          # 'opus'   — tier by task
```

Gate-adjacent reviewers (`code-reviewer`, `silent-failure-hunter`,
`type-design-analyzer`, `pr-test-analyzer`) may not be "tier by task", because a
T0 task would resolve them to the cheap tier. `assert_builtin_policy` rejects
that configuration.

---

## Deriving this for your own repo

Do not inherit our numbers. The tiering above came from measurement on one
codebase, and the class boundary — where "mechanical" ends and "thoroughness-
critical" begins — depends on what your code actually looks like.

1. **Pick real tasks, not benchmarks.** Take 8–12 closed issues from your own
   history, spread across the classes you care about (a mechanical refactor, a
   parser change, a schema migration, a doc update).
2. **Run each at two tiers**, same prompt, same acceptance criteria, isolated
   worktrees.
3. **Judge blind, at the top tier.** The judge must not know which tier produced
   which output, and must not be the model under evaluation.
4. **Score coverage separately from correctness.** This is the step that matters.
   "Did it work?" will show parity where "did it handle every input the issue
   implies?" shows a gap. Count the acceptance criteria silently skipped.
5. **Move down only where coverage held.** Cost parity on a correct-but-incomplete
   answer is not a saving; it is a deferred defect.
6. **Never include the floor in the sweep.** There is nothing to learn there — the
   asymmetry above already decided it.

Record the result somewhere durable and cite it in the catalog comment, the way
the shipped entries do. A retier with no recorded justification is indistinguish-
able from a guess six months later.

---

## Measuring where the money actually goes

Before optimizing, find out what you are spending on. `loop.spend` classifies
every agent call by how freely it could be re-routed:

```python
from software_factory.loop.spend import token_share, render
print(render(token_share(records, prices={"opus": (15.0, 75.0), ...})))
```

It reports a `movable_share` (the ceiling on any re-routing saving) and a
`move_now_share` (the subset already confirmed at parity). Roles it does not
recognize classify as `unknown` and are **never** counted as movable — an
unassessed role must not inflate the case for a change you are about to make.

Prices come from your manifest, not from this package; an unpriced model returns
`None` rather than being silently counted as free.
