# Reading Go in this repo: a guide for JS and Python developers

You don't need to *write* Go to review this agent. You need to read it. Go has very few features, and the code
here uses fewer still. This guide covers everything the agent uses, with examples taken from this codebase,
then gives you a reading order and a review checklist.

How the agent works as a system (processes, files, flows) is in [INTERNALS.md](INTERNALS.md).

---

## 1. Ten-minute crash course

### Packages and visibility

```go
package pairing                    // every file starts with its package name; the folder = the package

import (
	"crypto/sha256"                // standard library
	"lablantern/agent/internal/config" // this repo (module name from go.mod + folder)
)

func Code(caFingerprint, secret string) string { … }  // Capital letter = exported (public)
func ask(ifi *net.Interface, …) []string { … }        // lower case = private to the package
```

- There is no `export` keyword. **Capitalised names are public, lower-case names are private.**
- `internal/` is special: only code inside `lablantern/agent` may import it. That is why everything lives there.
- An import is always used as `packagename.Thing`, e.g. `config.LoadConfig(...)`, like `import * as config`.

### Variables and types

```go
url := strings.TrimRight(*master, "/")   // := declares + assigns, type is inferred (like `let`)
var authRejected bool                    // var declares with a zero value (false, 0, "", nil)
var longPollWait, retryDelay = 45, 60 * time.Second
```

Types come *after* the name: `func New(serverURL, agentToken string, caPEM []byte) (*Client, error)`.
Read that as `New(serverURL: string, agentToken: string, caPEM: Uint8Array): [Client, Error]`.

| Go | JS / Python equivalent |
|---|---|
| `string`, `int`, `int64`, `bool` | string, number, bool |
| `[]byte` | `Uint8Array` / `bytes` |
| `[]string` (slice) | array / list |
| `map[string]bool` | `Record<string, boolean>` / `dict` |
| `any` | `unknown` / `object` |
| `*Config` (pointer) | a reference to a Config object (may be `nil`) |
| `&cfg` | "give me a reference to cfg" |
| `nil` | `null` / `None` |

Pointers look scary but in this code they only ever mean "pass this object by reference" or "this may be nil".
You never see pointer arithmetic.

### Structs and JSON tags (= TypeScript interface + serializer)

```go
type Config struct {
	ServerURL     string `json:"server_url"`
	AgentToken    string `json:"agent_token"`
	SystemID      int    `json:"system_id,omitempty"`
}
```

The backtick part is a *tag*. `encoding/json` uses it for the field name in JSON. `omitempty` means "leave it
out if zero". `json.Unmarshal(data, &cfg)` is `cfg = JSON.parse(data)` **plus** type checking: unknown fields
are ignored, and fields with the wrong type cause an error.

### Methods

```go
func (p Paths) Submit(req Request) error { … }
//    ^^^^^^^ the "receiver": this makes Submit a method on Paths, called as p.Submit(req)
```

`(p Paths)` plays the role of `this`/`self`, and it gets a name. There are no classes and no inheritance.
A struct plus its methods is all there is.

### Errors instead of exceptions (you'll see this pattern everywhere)

```go
data, err := os.ReadFile(path)
if err != nil {
	return nil, fmt.Errorf("cannot read configuration (%s): %w", path, err)
}
```

- Functions return `(result, error)`. The caller **must** check `err`. Nothing is thrown.
- `fmt.Errorf("...: %w", err)` wraps the error (like `new Error(msg, { cause })`).
- `errors.Is(err, os.ErrNotExist)` checks the cause chain (like `err.code === 'ENOENT'`).
- `_ = something()` or `x, _ := f()` deliberately **ignores** a value or error. When you review, every `_` on an
  error is worth a glance: is ignoring it safe here?

### Control flow

```go
switch c.Type {            // no fall-through, no `break` needed
case "report_now":
	…
case "reboot", "update_agent", "uninstall":
	return runSigned(cl, c)
}
return "rejected", …       // reached only if no case returned

switch {                   // switch with no value = if/else-if chain
case e.SystemID == 0 || c.SystemID != e.SystemID:
	return rejected("command is for another system")
case now > c.ExpiresAt:
	…
}

for _, id := range needed { … }   // for…of; `_` drops the index
for time.Now().Before(deadline) { … } // while loop
for { … }                          // while (true)
```

### `defer` = `finally`

```go
resp, err := hc.Get(url)
…
defer resp.Body.Close()   // runs when the surrounding function returns, whatever path it takes
```

### Swappable functions for tests

```go
var imageSBOM = images.SyftSBOM      // main.go
var restartDaemon = func() bool { … }
```

A package-level variable that holds a function is how this repo does dependency injection: tests assign a
fake. When you see `var x = someFunc`, read it as "replaceable in tests". It is not runtime configuration.

### Concurrency (used in exactly one place: `internal/discover`)

```go
var wg sync.WaitGroup
for _, ifi := range ifaces {
	wg.Add(1)
	go func(ifi *net.Interface) {  // `go` starts the function concurrently (a goroutine)
		defer wg.Done()
		…
		mu.Lock(); found[u] = true; mu.Unlock()   // protect the shared map
	}(ifi)
}
wg.Wait()                          // like await Promise.all(...)
```

Everything else in the agent is plain sequential code.

### Running external programs (no shell)

```go
exec.Command("dpkg-query", "-W", "-f=${Package}\t…").Output()
```

The arguments go straight to the program as an argv array. There is **no shell**, so `$`, `;` and `|` inside an
argument have no special meaning. This is like `child_process.execFile`, not `exec`. Every `exec.Command` call in
this repo has fixed arguments.

---

## 2. Tools

| Task | Command (in `agent/`) |
|---|---|
| Run all tests | `CI=true go test ./... < /dev/null` |
| Static checks | `go vet ./...` |
| Build | `go build ./cmd/lablantern-agent` |
| Show docs of a symbol | `go doc ./internal/passkey Verify` |
| Who calls X? | VS Code with the Go extension: right-click → *Find All References* |

Install the **Go extension for VS Code** (it brings `gopls`). Hovering shows types, F12 jumps to definitions.
That alone makes reviewing much easier.

---

## 3. Reading order (about 2,700 lines without tests)

Read in this order. Each step builds on the previous one.

1. `cmd/lablantern-agent/main.go`: the entry point. `run()` dispatches the sub-commands (`setup`, `enroll`,
   `daemon`, `collect-job`, `action-job`, `scan`). Skim it first to see the shape.
2. `internal/config/config.go`: what is stored in `/etc/lablantern/agent.json` and how the pinned CA is validated.
3. `internal/client/client.go`: every HTTP call to the master. `FetchCA` is the only place that skips TLS
   verification, and its comment says why.
4. `internal/collector/collector.go`: what is collected (os-release, dpkg/rpm, apt security updates, Docker
   containers).
5. `internal/jobs/jobs.go`: how the unprivileged daemon and the root collector talk through files.
   `ReadNoFollow` is a key security primitive here.
6. `internal/queries/queries.go`: the four fixed read-only queries.
7. `internal/passkey/passkey.go`: WebAuthn signature verification inside the agent. This is the heart of the
   "the master alone can't reboot a host" guarantee.
8. `internal/actions/actions.go`: the root side of reboot / update / uninstall and of the passkey trust list.
9. `internal/release/release.go` and `cmd/ll-release/main.go`: signed release manifests (Ed25519).
10. `internal/pairing`, `internal/discover`: `setup` via mDNS plus the pairing code.
11. `internal/images/images.go`: a thin wrapper around the Syft library.
12. `packaging/`: the systemd units and their sandboxing, tmpfiles, and package scripts. These matter as much as
    the Go code.

Each package has a `_test.go` file next to it. The tests are often the quickest way to see what a function is
*supposed* to do.

---

## 4. Review checklist for changes to the agent

Use this when you review a diff (yours or an AI's):

- **New command type?** It must appear in `runCommand` (`main.go`) **and** in the server allowlist
  (`commands.py` / `passkeys.py`). Dangerous ones must go through `runSigned` → `actions` (root, passkey
  check), never run in the daemon.
- **New `exec.Command`?** Fixed program, fixed arguments, absolute path where possible, nothing from the
  network in the argv.
- **New file read as root?** Use `jobs.ReadNoFollow` or `jobs.TakeFile` for anything inside `/run/lablantern`
  (the daemon controls that directory).
- **New file written as root?** Use `jobs.WriteAtomic`, and check the file mode it ends up with (currently 0644).
- **TLS:** `InsecureSkipVerify` must stay limited to `FetchCA`. Every other request uses `client.New` with the
  pinned CA.
- **Ignored errors (`_ =`)**: is a silent failure safe here?
- **Size limits:** every `io.ReadAll` should be wrapped in `io.LimitReader`.
- **systemd units:** a new path the root side writes must be listed in `ReadWritePaths`. Don't loosen
  `PrivateNetwork=yes` on the root units.
- **Tests:** `go test ./...` must pass; security-relevant branches (rejections) should have a test case.
