# The drill project: standing configuration

The isolated project `drill` used by schema rehearsals and the quarterly
restore drill (DRILL.md). Its standing configuration, kept current by the
same change process as any other project:

* **No network route to production**: the project sits in its own network
  with no peering to the production network; nothing in it can reach the
  production archive's endpoints.
* **Credentials**: the project's service account holds exactly one grant
  outside the project - READ on the backup store (`archive-backups`). It has
  no production-project roles of any kind.
* **Disposable**: recreated from this standing configuration for each
  drill or rehearsal and torn down at the end of it; nothing
  else depends on it, so teardown is routine, not risky.
