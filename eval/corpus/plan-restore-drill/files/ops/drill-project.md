# The drill project: standing configuration

The isolated project `drill` used by schema rehearsals and the quarterly
restore drill (DRILL.md). It is recreated with one platform command from the
change-controlled template `ops/templates/drill-standing-config.yaml` (in
this repository, beside this note); this document DESCRIBES what that
template pins, for reviewers - the template, not this file, is what
recreation applies, so quarterly recreation cannot drift from it by hand.

* **No network route to production**: the template places the project in its
  own network with no peering to the production network; nothing in it can
  reach the production archive's endpoints.
* **Credentials**: the template gives the project's service account write
  authority INSIDE the drill project only (it is the restore target - without
  that the drill cannot run), exactly one grant outside the project - READ on
  the backup store (`archive-backups`) - and no other-project roles of any
  kind, production included.
* **Disposable**: recreated from the template for each drill or rehearsal
  and torn down at the end of it; nothing else depends on it, so teardown is
  routine, not risky.
