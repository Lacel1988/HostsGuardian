# Linux Engine Monitor source checkpoint

Monitor source is now prepared under `linux-monitor/`, with an optional local
Engine status publisher. See [source/package/validation notes](../linux-monitor/README.md).
Actual GTK, D-Bus, systemd, polkit, packaging, graphical login and permission checks
require Vivo. No deployment or runtime changes have been performed on Windows.
The Engine remains independent; Windows WPF remains the policy control plane.
