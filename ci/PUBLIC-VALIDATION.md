# Frozen guardrail package validation candidate

This public repository is a separate validation destination with fresh history.
It does not replace or expose the Git history of the original private repository.
Production launch remains DISABLED. No local installation or research workload is
authorized. The proposed Windows package behavior is UNEXECUTED until an actual
retained hosted receipt demonstrates it. Prior engine tests do not validate the
embedded runtime or the packaged resource floor.

The frozen package is PC-Stability-Guard-0.1.2-pkg.1.zip, 11600050 bytes, SHA256
`a6a7a8a698819c0d0cde2e36dfe86e2afd256db26668315f616cec533c384310`.
It contains the tested0.1.2 engine, unchanged official Python3.13.16 AMD64 embedded
runtime (34 vendor files), notices/provenance and package scripts/docs. All86
archive files are verified against the frozen manifest. No runtime download,
upgrade or dependency installation is part of the workflow. UCRT must exist on
the runner. The app/__pycache__ zero-byte regular-file sentinel remains immutable.
The external packaging/pkg.1/Package.ps1 is identical to the ZIP entry.

The ZIP preserves historical source-review documentation, including links into a
private repository, synthetic historical run identifiers/digests, an opaque Cloud
environment identifier and generic/placeholder paths. These are historical source
metadata, not raw production evidence. Its bytes were deliberately not sanitized
or rebuilt. Python/vendor licenses and public author attributions remain intact;
no new open-source license for the guardrail code is asserted by this publication.

The owner authorized at most SIX total fresh manual windows-latest package runs,
each job max10min (aggregate60min), on this separate public repository
ID1428899604. Root stops at the first PASS, preserves every failure and reviews
bounded repairs before each later dispatch. All six were unspent at preparation.
This source proposes the first run only; no automatic retry or job rerun. Use
reviewed main commit SHA and approval PACKAGE-ONLY-ONE-RUN. No push/PR/schedule
trigger, no self-hosted runner, no automatic retry or job rerun. Contents permission is read-only;
official checkout/upload actions are pinned by full commit. Root records each fresh run ID/commit/outcome/duration to enforce the six-run
maximum and stop-at-first-PASS boundary. Attempt2 is refused by code.

The actual test order is context/digests, native PowerShell ParseFile, unchanged
InspectArchive, fresh Stage at the actual per-user LocalApplicationData fixed
leaf, InspectInstalled and vendor/sentinel hashes, finite isolated import probe,
Status once, Baseline once, Normal once only after Baseline PASS, post-Normal
hashes/receipts, then evidence-preserving stopped-state Quarantine. No arbitrary
path, package, threshold, code or workload input is accepted. Parse inner receipt
stdout, not the wrapper's mixed JSON/RECEIPTS_PRESERVED output.

Baseline and Normal each keep >=8GiB available physical and >=6GiB commit
headroom. Public Windows runners are documented16GB TOTAL, which makes the floor
feasible but does not establish actual headroom. A capacity refusal is FAIL, with
dependent cases UNEXECUTED. Status/imports do not imply workload admission. No
CI-synthetic floor override is supplied. The permanent Normal marker is written
by the unchanged wrapper before its own preflight, so any attempted Normal is
never repeated/reset. All first errors, nonzero exits and receipts are preserved.

Normal is finite0.5s sleep plus a small receipt. Original workload limits remain
2 active in-job processes,256MiB job/192MiB per-process,20% CPU,8s user CPU,wall20s.
All in-job processes count. Watchdog remains1 process,128MiB job/96MiB process,
5% CPU,8s user CPU,absolute28s. A10s command-start deadline is earlier intervention, not a limit increase.
Every package/probe command is created atomically inside a separate owner Job
Object, suspended until membership is checked, with only KILL_ON_JOB_CLOSE set
and no breakaway allowed. Original package/workload/watchdog caps stay unchanged.
A timeout immediately terminates that owner job (including the preflight wrapper,
controller and nested jobs), then requires the exact wrapper handle signaled and
outer accounting active0 within3s. No guard-stop/NO_IDENTIFIED_JOB or30s wrapper
admission grace remains. Failure and cleanup errors stay separate; handle closure
is a kill backstop, not exit proof. No PID/name/global kill or retries. If membership observation or tree termination
fails, an exact returned wrapper-handle fallback prevents that wrapper from
continuing, with up to3s wait; it does not substitute for descendant/job exit proof.

The reviewed ci/OwnedCommand.cs helper is compiled once on the hosted runner with
its existing Framework64 compiler; source/compiler/version/output hashes are
recorded. /noconfig excludes default response files; no analyzers or arbitrary
source inputs. Compile<=30s plus3s termination, source<=32KiB/output<=256KiB;
no install or runtime/security update. The resulting DLL lives outside the frozen
package and is not uploaded as evidence. Compilation, native ABI and nested-job
behavior remain prospective; Cloud performs inert source checks only.

Harness active phase<=300s and evidence<=360s, plus compiler<=33s, within existing
step7min/job10min. Commands have8–45s deadlines and64KiB output checks. The parent
owner job has no added resource caps; finite code/waits are not OS-wide resource
quotas or hard real-time scheduling guarantees. Last-handle closure protects the
owned tree if the harness dies. Hard job-timeout evidence is best effort.
No active-stop, hang, concurrency, negative reparse, partial rollback or full21
suite exercise is added. The single Normal admission does not establish that
all timeout/crash branches have executed. Those paths remain UNEXECUTED.

Artifacts retain original generated receipts, unique run ID/attempt names,
overwrite=false and requested90day retention (subject to repository maximum).
Evidence is bounded at512files/32MiB; failed bounds preserve a partial control
artifact and FAIL. Mutable snapshots copy only exact package state/scratch/local
evidence, checking links, depth, file count and sizes. Healthy quarantine runs
the identical external script outside the staged tree after exit confirmation;
all frozen hashes and bounded mutable snapshot hashes must remain identical.
On failure, the original tree stays until ephemeral runner disposal; no forced
quarantine, erase, cleanup retry or success relabeling is performed.

No execution policy, MOTW/Zone.Identifier, ACL, trust, Defender, firewall, PATH,
registry, service or startup changes. A blocked script is a retained failure;
no bypass, Unblock, alternate script execution or installer repair is permitted.

Applicable official documentation, retrieved2026-10-21:

- https://docs.github.com/en/actions/reference/runners/github-hosted-runners — public16GB/private8GB table; actual floor still checked.
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows — workflow_dispatch discovery requires default-branch file.
- https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parsefile?view=powershellsdk-7.4.0 — native static parser with error array.
- https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.waitforexit?view=netframework-4.8.1 — bounded Int32 wait versus infinite parameterless wait.
- https://raw.githubusercontent.com/actions/checkout/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml — exact action pin inspected.
- https://raw.githubusercontent.com/actions/upload-artifact/cf430e030ddbb5b0abf93d22962f4752f3646cd9/action.yml — exact action pin, immutable artifacts/retention.

Primary pages were retrieved by the originating review chat; Cloud direct
primary-page requests returned403, preserved in its private preparation review.
Official raw documentation and exact action metadata were retrieved in Cloud.
No network or security policy change was used for this test preparation.

Timeout control-flow remediation was preceded by a short pinned PowerShell5.1/
.NET Framework4.8 official issue/release/troubleshooting check on2026-10-21.
No applicable vendor bug/fix was identified; bounded waits do not terminate child
processes, so the old harness grace path was corrected in source. Relevant docs:

- https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs — inheritance, aggregated accounting and descendant-job termination.
- https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject — associated processes cannot postpone termination.
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute — atomic JOB_LIST and explicit inheritable HANDLE_LIST.
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-5.1 — caller-independent process lifetime.

Historical source commit d056004615142e161f7ea94cc27541d71d6b6dbb and its artifacts
are preserved. Its timeout path is superseded; no hosted test had been dispatched.
