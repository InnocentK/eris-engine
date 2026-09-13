# The drill project: standing configuration

The isolated project `drill` used by schema rehearsals and the quarterly
restore drill (DRILL.md). It is recreated with one platform command from the
change-controlled project template `drill-standing-config`; this document
DESCRIBES what that template pins, for reviewers - the template, not this
file, is what recreation applies, so quarterly recreation cannot drift from
it by hand.

* **No network route to production**: the template places the project in its
  own network with no peering to the production network; nothing in it can
  reach the production archive's endpoints.
* **Credentials**: the template grants the project's service account exactly
  one role outside the project - READ on the backup store
  (`archive-backups`) - and no production-project roles of any kind.
* **Disposable**: recreated from the template for each drill or rehearsal
  and torn down at the end of it; nothing else depends on it, so teardown is
  routine, not risky.
