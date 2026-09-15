# macOS Permission Helper

A small macOS broker that gives OpenCode2 a durable TCC identity. It runs
as a launchd agent out of a stable app bundle, and spawns one signature-verified
target binary on request. Permissions you grant to the bundle once (Full Disk
Access, Screen Recording, Accessibility) then apply to every run of that target,
including runs started from cron, launchd, or an ssh session.

This fork defaults to OpenCode2 and verifies OpenCode's Developer ID signature.
The target path and code-signing requirement remain configurable.

## The problem

macOS gates privacy-sensitive access (TCC) on the code identity of the
*responsible* process for a request. Two things follow, and together they make
permissions for a headless CLI effectively unmaintainable:

**Grants die on update.** Claude Code installs each version at its own path
under `~/.local/share/claude/versions/<ver>`, with `~/.local/bin/claude` as a
symlink. TCC keys the grant to the binary it saw, so the next auto-update
orphans it. You re-grant, and lose it again in a few days.

**Grants made interactively never covered automation anyway.** When launchd
starts a process, that process becomes its own responsible process. A cron job
running `claude -p ...` is therefore attributed to itself, not to your terminal,
so the Full Disk Access you granted Terminal or iTerm does nothing for it. The
symptom is a script that works when you run it by hand and returns `Operation
not permitted` on a schedule.

## The mechanism

Five points. The first two are the design; the rest are the tradeoffs you are
accepting.

**1. Responsibility is inherited downward, and only reassigned at the top of a
tree.** TCC responsibility passes through `fork`/`exec` to children, and is
reassigned when launchd spawns a process (or LaunchServices launches an app).
This is why a per-invocation wrapper does not work: a wrapper binary exec'd in
the middle of a cron job's process tree inherits the cron job's identity no
matter what grants the wrapper itself holds. The thing holding the grant has to
be at the top of its own tree. So claudehost is a long-running launchd agent
living in a stable bundle, and the target runs as *its* child, inside its
granted identity.

**2. Caller gating is not enforceable on a same-user socket; target gating is.**
Any process running as you can connect to your unix socket. Peer credentials
(`LOCAL_PEERCRED`) tell you the uid, which is the same uid. Walking the parent
chain and checking what the caller is proves nothing, since a caller can arrange
its own parentage. The enforceable equivalent is to invert it: the server
accepts no target binary from the caller at all. It resolves the one target path
it was configured with at startup and verifies that binary against a designated
code-signing requirement before every spawn. Driving the socket can only ever
mean "run the verified target with these arguments", which is exactly the
authority the broker was created to hand out.

**3. Ad-hoc signing means every rebuild orphans the grants.** With `codesign -s
-`, the app's TCC identity is its cdhash, so changing a byte of the binary makes
it a different app as far as TCC is concerned, and you re-grant it in System
Settings by hand. This is a real cost and the reason to rebuild deliberately
rather than casually. `make SIGN_ID="Developer ID Application: ..."` avoids it if
you have a certificate; a persistent self-signed codesigning identity from
Keychain Access also works, and grants survive rebuilds as long as the signing
identity is stable.

**4. Same-user attackers are out of scope.** Anything running as your user can
replace the app bundle in `/Applications` (user-writable by default), edit your
LaunchAgent, or just read the files you were protecting. The broker does not
change that and does not try to. What it defends against is a *mistake*: an
automation, script, or agent driving the socket cannot use it to run something
other than the verified target. Two hardening steps are documented but not done
here, both requiring sudo per update: root-owning the app bundle so it cannot be
swapped, and closing the TOCTOU window between verifying the target binary and
spawning it.

**5. This leans on TCC behavior Apple does not document as a contract.**
Specifically: that responsibility is inherited by children, and that a
launchd-spawned process is responsible for itself. Both have been stable for
years and are what the observable behavior of the system implies, but they are
not promised anywhere, and no better primitive is exposed. If a future macOS
changes attribution, the failure mode is grants stopping working again, which is
the status quo ante rather than a new hazard.

## Permission setup

Open `/Applications/MacOSPermissionHelper.app`, then use each **Grant…** button
for Full Disk Access, Local Network, Reminders, Accessibility, and Screen &
System Audio Recording. macOS requires user approval in its prompt or System
Settings; the helper reports public permission status where macOS provides it.
Restart the helper and OpenCode services after changing grants.

## Quickstart

Requires macOS and the command line developer tools. No other dependencies.

```
git clone https://github.com/felixfoertsch/macos-permission-helper
cd macos-permission-helper
make                # signs with Felix's stable Developer ID by default
make install        # installs /Applications/MacOSPermissionHelper.app
```

Confirm the target verifies before going further:

```
/Applications/MacOSPermissionHelper.app/Contents/MacOS/macos-permission-helper \
  --claudehost-check "$(readlink ~/.local/bin/opencode2)"
```

Install the agent. Copy
`examples/de.felixfoertsch.macos-permission-helper.plist` to
`~/Library/LaunchAgents/`, then:

```
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/de.felixfoertsch.macos-permission-helper.plist
```

It has to be a LaunchAgent in the gui domain, not a LaunchDaemon: TCC grants are
per-user, and the broker runs the target as you.

Grant permissions to the bundle. System Settings, Privacy & Security, Full Disk
Access, `+`, `/Applications/ClaudeHost.app`, enable. Other permissions can be
granted the same way or accepted on first prompt; prompts triggered by the
target now attribute to ClaudeHost, so they stick.

Wire your callers to the broker. The client mode is argv-compatible with the
target, so this is a path substitution:

```sh
CLAUDE_BIN=/Applications/ClaudeHost.app/Contents/MacOS/claudehost
[ -x "$CLAUDE_BIN" ] || CLAUDE_BIN=claude
"$CLAUDE_BIN" -p 'whatever'
```

The client falls back on its own too. If the socket is unreachable it prints a
loud warning to stderr and execs the target directly, so an automation degrades
to its pre-claudehost behavior visibly (the warning lands in the job log)
instead of failing.

## Acceptance test

The point of the thing is a difference in behavior between brokered and bare, so
test for that difference rather than for "it ran".

```
CH=/Applications/ClaudeHost.app/Contents/MacOS/claudehost
P='Run: ls ~/Library/Mail && echo FDA-OK. Reply with the last line only.'

$CH    --model haiku --permission-mode bypassPermissions -p "$P"   # expect FDA-OK
claude --model haiku --permission-mode bypassPermissions -p "$P"   # expect the ls to fail
```

`~/Library/Mail` is FDA-gated, so the bare run should report `Operation not
permitted` and the brokered one should not. Any FDA-gated path works; use one
you actually have.

Re-run the brokered half after the next auto-update, with no re-granting. That
is the claim worth checking, and it is worth automating: have a daily job record
the target's resolved version, and when the version changes, re-run the probe
through the broker and alert if it fails. Update survival then verifies itself
instead of depending on someone remembering to re-test.

## Interface

```
claudehost --claudehost-serve [--target PATH] [--requirement REQ] [--socket PATH]
claudehost --claudehost-check PATH [--requirement REQ]
claudehost <args...>            # client; behaves like `<target> <args...>`
```

Server options are read once at startup and never from a request. Defaults:
target `~/.local/bin/claude`, Anthropic's designated requirement for
`com.anthropic.claude-code`, socket
`~/Library/Application Support/ClaudeHost/claudehost.sock`.

To broker something other than Claude Code, read the requirement off the
binary with `codesign -d -r- <path>` (take the text after `designated => `) and
pass it to `--target` and `--requirement` in the plist. Two environment
variables are read by both sides: `CLAUDEHOST_SOCKET` selects the socket, and
`CLAUDEHOST_TARGET` sets the binary the client direct-execs when it falls back.
On the server they supply the defaults for `--socket` and `--target`, so an
explicit flag in the plist beats whatever environment launchd hands the agent.

The client passes argv, environment, cwd, and its real stdio file descriptors
(over `SCM_RIGHTS`), so pipes, redirection, and PTYs work unchanged. Exit codes
are mirrored, including `128+signal`. Signals the client receives are forwarded
to the child's process group, so `timeout`/`gtimeout` behave normally. If the
client dies without cleanup, the server terminates the child tree.

Client exit codes: the child's exit status, or `95` if the server refused
(verification or spawn failure), `96` on protocol error, `97` if the broker was
unreachable or vanished mid-run, or the direct-exec fallback itself failed.

Logs go to stderr, which the example plist routes to
`~/Library/Logs/com.example.claudehost.err.log`. Signature verification results
are cached by dev/ino/size/mtime, so the roughly half-second full-binary hash is
paid once per target version rather than per call.

## Things to do instead of this, and why they do not work

**Grant Full Disk Access to `/bin/bash`, `/usr/sbin/cron`, or your terminal.**
This works, and it grants FDA to everything those programs ever run, with no
gate of any kind. It is a strictly larger grant than the one claudehost makes,
handed to a much less specific identity.

**Ship a small wrapper binary, grant it FDA, and have cron call it.** This is
the intuitive design and it does not work. The wrapper is exec'd inside the cron
job's process tree and inherits that tree's TCC responsibility; its own grants
are not consulted. You get a wrapper with permissions that its children cannot
use. Only a process at the top of its own launchd-spawned tree holds an identity
that children inherit, which is why the broker is long-running.

**Have the broker run whatever the caller asks for, and check who the caller
is.** Same-user callers cannot be authenticated to each other, so the check is
decoration. If the broker will run arbitrary binaries, then FDA on the broker is
FDA for every process on the machine that can open a socket.

**Re-grant after each update.** That is the problem, and if the automation is
what needs the grant, interactive re-granting does not even solve it.

## Status

Built for and running in production on the author's machines, where it brokers
the scheduled Claude Code fleet and remote-control sessions. The behaviors
described above (exit codes, stdio passthrough, signal forwarding, orphan
reaping, signature refusal, verification caching) are covered by manual tests;
there is no test suite. The interface may change. Issues and patches welcome.

MIT licensed.
