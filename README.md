# Windows Crash Root Cause Analyzer

Read-only Windows 11 event correlation for unexpected shutdowns, restarts and bugchecks.

## Requirements

Windows 11 with built-in Windows PowerShell 5.1. Keep the BAT and PS1 together.
No installation is needed. Start without administrator rights; the tool never elevates itself.
Organization policy may block scripts.

## Usage

Open Command Prompt in the downloaded folder. In PowerShell, prefix BAT commands with `.\`.

```bat
crash-analyzer.bat help
crash-analyzer.bat analyze
crash-analyzer.bat analyze -Days 3 -IncidentTime "2026-10-21T18:00:00-07:00"
crash-analyzer.bat collect -Days 1 -OutputFolder "C:\Captures\new evidence"
crash-analyzer.bat report -InputFile "C:\Captures\new evidence\evidence.json" -OutputFolder "C:\Captures\new report"
```

Quote paths containing spaces. Incident times require ISO 8601 with an offset or `Z`.
The default window is seven days. `help` lists other options.

## Behavior

`analyze` collects evidence and creates JSON, text and self-contained HTML reports.
`collect` saves evidence; `report` reads the tool's version 1.0 evidence JSON offline,
rather than raw EVTX or dump files. Collection is bounded; restricted or timed-out
sources remain visible as gaps.

Kernel-Power 41 alone cannot identify a failed component. Nearby updates and hardware
warnings may be unrelated; a bugcheck identifies a crash mechanism, not its root cause.

## Outputs

`collect` writes `evidence.json`. Output defaults to a new local `output/` subfolder
beside the script; a chosen folder must be new or empty and local. Reports are never overwritten.
The console prints output paths and missing evidence. Exit 0 includes partial collection:
check `Coverage` and `EvidenceGaps`. Exit 1 means invalid input or an operational failure.

## Safety and privacy

No settings, drivers, services, logs or crash configuration are changed. No reboot,
repair, download, telemetry or upload. Dump files are inspected for metadata only.
Reports omit identities, private paths and free-form messages, but times and system
build details may still identify a machine. Review reports before sharing.

## Troubleshooting

`crash-analyzer.bat help` should exit 0. An invalid command should exit 1 without
collecting events. Run in a terminal to retain errors. Restricted or timed-out
sources appear in `EvidenceGaps`; missing evidence cannot establish a cause.

Report issues with the command, Windows version, exit code and expected/actual result.
Omit real event data and identifying reports.
