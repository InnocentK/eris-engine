# Rollout plan: enable the new review pipeline for all teams

## Goal

Move every team from the single-reviewer pipeline to the new multi-reviewer
pipeline, and decide from the rollout data whether to keep it.

## Phases

* **Week 1** - two volunteer teams, both already familiar with the tool.
* **Week 2** - ten teams chosen at random from those who opted in.
* **Week 3** - everyone, unless a stop condition below has fired.

## Success metric

We keep the new pipeline if it **halves the confident-error rate** at no more
than twice the cost.

A review is a "confident error" when the reviewer marks a finding `critical` or
`high` and that finding turns out to be wrong. The severity is the one the
reviewing model assigns to its own finding. We collect no other confidence
signal from the reviewer.

## Stop conditions

Roll back immediately if any of these fire:

* median review latency above 90 seconds;
* cost per review above $0.40;
* any data-loss incident, of any size.

## Who decides

The pipeline team owns the rollout. A stop condition is evaluated by whoever is
on call, and either of the two pipeline leads can halt a phase without waiting
for the other.

## Cost accounting

Cost per review is the sum of every model call the review made, including
retries and the calls a review makes before being abandoned. We attribute
abandoned work to the phase that started it, not the phase it finished in.

## Communication

Each phase is announced in the engineering channel the working day before, with
the stop conditions restated. Teams entering a phase get a short note on what
changes for them; teams already in one get nothing further.

## Training and support

No training is planned. The reviewer interface is unchanged, and the difference
is in how many reviewers a change is shown to. Support questions go to the
existing channel.

## Scope of the pre-flight lint

Before each phase we lint the config files that the pipeline reads. The linter
checks every file under `config/pipeline/` and `config/teams/`. Anything it
flags blocks the rollout for that phase.

## Deliberately not doing

* **No automatic rollback.** A human decides, because an automatic rollback on a
  latency spike would thrash during a normal traffic peak. Latency is a stop
  condition a human evaluates, not a trigger.
* **A one-week canary per phase.** Shorter would not survive a weekly cycle;
  longer delays the decision past the quarter. One week is the deliberate
  choice, not an oversight.
