# Factory doctrine

The brief for **one agent session working one issue**. It replaces the 0.x
orchestration doctrine of persona teams, judge panels and digest approvals:
current frontier models plan, implement and verify better inside a single
session than across a relay of handoffs.

## 1. Read and size the work

Read the issue in full, including its **Expected outcome**. Size it with the
deterministic helper, so the floor is enforced rather than remembered:

```
python3 -c "from software_factory.core.orchestrate import classify_tier; print(classify_tier(source='feature', files_changed=8, lines_changed=300))"
```

You may size up (say why), never silently down. Thresholds come from config
(`factory.routing.thresholds`).

- **T0/T1, and every bug, chore or tech-debt item:** proceed.
- **T2 feature:** post a short plan as an issue comment (approach, files
  touched, risks, how it will be verified) and **stop until a human approves
  scope**. That is the only pause in the loop.

## 2. Do the work in this session

- Plan, implement and test here. Do not hand off to sub-agents for work you can
  hold in context; use them only for wide read-only searches.
- Write the failing test first, against the Expected outcome.
- Run the project's `verify_cmd` until it passes. Never claim a test, build or
  check ran if it did not.
- Keep the change scoped to the issue. Note anything else you find as a
  follow-up instead of fixing it here.

## 3. Hand off through a PR

Open a PR into the configured dev branch with:

- what changed and why, linked to the issue;
- how it was verified (commands run and their results);
- anything a reviewer should look at closely.

CI then runs the tests and the secret and public-content scan, and one
independent review comes from a different model. Address review comments in
the same branch.

## 4. The standing limit: the human owns what cannot be undone

**Human decisions — always, every time:**

* **production releases:** merge to a production ref, deploy, publish, any
  production write;
* **scope:** a T2 feature waits for plan approval (§1);
* **policy:** what the gates are, what the budget is, what counts as done.

**Everything else runs unattended**, and is made safe to run unattended by
gates that are code: the project's tests in CI, the content scan, the
independent review, branch rulesets on `main`, and credentials that cannot
merge or deploy. Never merge, tag, release or deploy, even when a tool would let
you.

**If anyone needs to review every diff line by line, the gates are too weak.
Fix the gates — do not add reviewers.**

* **A gate must be code, not an instruction.** Anything a model is asked to
  remember can degrade under a long context or a persuasive reason to skip it.
  Prefer gates the platform enforces (CI, rulesets, permission settings) over
  gates written here.
* **Reversibility is the whole argument.** Autonomy is safe in proportion to
  how cheaply a mistake is undone. That is why the dev branch is a sandbox, the
  production boundary is absolute, and merge and deploy are never granted to an
  agent.

Secrets stay in the environment or local files and are never written to a
committed file or log.
