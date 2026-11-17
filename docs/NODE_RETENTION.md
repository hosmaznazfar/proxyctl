# Node retention and permanent purge

`remove` is intentionally reversible: it soft-deletes a node so it can still be restored. `nodes purge` is the irreversible cleanup step.

## Preview and apply

Preview every soft-deleted node (the default age is `0s`, so all deleted nodes are eligible):

```sh
proxyctl nodes purge --deleted
```

Permanently remove eligible nodes and their node-specific benchmark data:

```sh
proxyctl nodes purge --deleted --apply
```

Keep a 30-day restore window:

```sh
proxyctl nodes purge --deleted --older-than 30d
proxyctl nodes purge --deleted --older-than 30d --apply
```

Durations accept seconds (`45s`), minutes (`45m`), hours (`12h`), or days (`30d`). The command always previews unless `--apply` is supplied. It never selects active nodes.

## What gets removed

The database operation is one atomic redb write transaction. For each purged node it removes:

- The node record and its fingerprint index entry.
- Every benchmark sample belonging to that node.
- The node ID from shared benchmark-run metadata.
- Any finalized benchmark run that becomes empty.

When a run contains other nodes, their samples and the shared run metadata are retained. A node referenced by a currently running benchmark is skipped. Monotonic ID counters are not reset or reused.

## Periodic cleanup with systemd (user service)

The recommended schedule preserves a 30-day restore window and runs daily. Create the user service and timer files:

```sh
mkdir -p ~/.config/systemd/user
```

```ini
# ~/.config/systemd/user/proxyctl-purge.service
[Unit]
Description=Permanently purge old soft-deleted Proxyctl nodes

[Service]
Type=oneshot
ExecStart=/usr/bin/env proxyctl nodes purge --deleted --older-than 30d --apply
```

```ini
# ~/.config/systemd/user/proxyctl-purge.timer
[Unit]
Description=Daily cleanup of old soft-deleted Proxyctl nodes

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=15m
Unit=proxyctl-purge.service

[Install]
WantedBy=timers.target
```

Enable it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now proxyctl-purge.timer
systemctl --user list-timers proxyctl-purge.timer
```

Inspect the last run:

```sh
systemctl --user status proxyctl-purge.service
journalctl --user -u proxyctl-purge.service
```

Disable periodic cleanup:

```sh
systemctl --user disable --now proxyctl-purge.timer
```

The service uses the `proxyctl` executable found by the systemd user manager's PATH. If it is not on that PATH, replace `/usr/bin/env proxyctl` in `ExecStart` with the absolute path printed by `command -v proxyctl`.

## Active-node age policy

Active nodes are deliberately not purged by age. The current record model has a creation timestamp but no reliable last-used timestamp; treating creation age or benchmark age as inactivity could destroy a node the user still relies on. To include an active node in retention cleanup, first soft-delete it explicitly with `proxyctl remove`, then let the deleted-node policy handle it.