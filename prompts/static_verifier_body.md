# Pass Awareness

This verifier runs on **both** static-analysis passes:

- **Bare pass** — the slice contains only call types (a)–(e). Outputs use only `sensitive_api` / `conditional_api` / `third_party` / `unresolved` / `sensitive_property` as `node_type` values.
- **Enriched pass** — the slice has been re-annotated with npm-registry metadata for previously undetermined third-party nodes. Type (f) annotations may appear, and `third_party_with_metadata` is then a valid `node_type`.

Apply every rule below **conditionally on what the slice actually contains**: if no type (f) annotation is present in `sliced_code`, every third-party reference is type (d), `third_party_with_metadata` must not appear in your output, and the type-(f) carve-outs do not fire.

---

# Judgement Definitions

## `"benign"`
Use when:
- The visible sliced code (plus any read file content provided by the header above) shows common, legitimate behavior.
- Sensitive APIs / properties appear in normal expected contexts.
- No clear malicious pattern is supported by the visible evidence.

## `"malicious"`
Use **ONLY** when:
- The malicious behavior is definitive from the visible code (plus any read file content provided by the header above).
- You can point to specific Node IDs that clearly prove malicious intent / behavior, such as:
  - Reading sensitive system / credential files and sending them outward
  - Executing hardcoded or clearly malicious commands
  - Downloading and executing suspicious payloads
  - Destructive file / system operations
  - Obvious backdoor / reverse-shell logic
  - **Decoding-then-executing pattern**: the slice contains an explicit decoding / deobfuscation step (`Buffer.from(..., 'base64').toString()`, `atob(...)`, hex / `\xNN` / `\uXXXX` decoding, `String.fromCharCode(...)` reassembly, split-join character tricks, ROT-N transforms, custom XOR / stream decoders, etc.) whose output flows into `eval` / `new Function` / `vm.runInThisContext` / `vm.Script` (or is written to a file that is then `require`d / executed). Legitimate template engines / expression evaluators do not need to deobfuscate their own templates — this chain is a hallmark of obfuscated payload loaders. Cite both the decode-site Node ID and the eval / executor Node ID. Network → eval or file → eval **without** such a decoding intermediary does NOT trigger this rule — see the handoff case in the `"undetermined"` definition below.
  - **Running a native binary shipped inside the package** — e.g. `spawn` / `exec` / `require` / `dlopen` targeting a package-local file with suffix `.exe` / `.dll` / `.so` / `.dylib` / `.bin` / `.node`, etc. We only analyze source code, so a binary payload cannot be verified — judge `"malicious"` directly and cite the spawn / load Node ID. Does **not** apply to system binaries on `PATH` (`node`, `npm`, `git`, `bash`, ...).
- The `reason` field **MUST** state the critical behaviors that led to the malicious judgement.

## `"undetermined"`
Use when:
- Suspicious patterns exist but final intent depends on runtime values or hidden semantics, including:
  - `conditional_api` nodes with unknown arguments or return values that cannot be inferred from the visible code context (note: if the slice provides enough context to determine the actual values, the node should NOT be treated as conditional)
  - `third_party` nodes (type d, no metadata) whose semantics may receive sensitive data or control sensitive operations
  - `unresolved` nodes that may hide dynamic dispatch or obfuscation
- The visible slice's primary effect is a **control-flow handoff to code that is not in the slice** — i.e., the call site itself carries no security-relevant payload of its own, and its net effect is to make some *other* code unit start running, whose body is **not** present in the current `code_snippet` / `callee_info`. Non-exhaustive patterns:
  - Spawning / forking a new process or worker to run a local script: `child_process.spawn/exec/execFile/fork`, `cluster.fork`, `new Worker(...)`, `"node <local_file>"`, etc.
  - Registering a local script with a process manager / supervisor: `pm2.start({ script: ... })`, `forever.start(...)`, `nodemon`, `pm2.connect` → `pm2.start`, and similar "run this file as a managed service" APIs.
  - Loading-then-executing code whose source is not statically visible: any chain that reads / receives a code-shaped string from an opaque source — a local file (`fs.readFile(localPath)` → `eval` / `new Function` / `vm.runInThisContext` / `vm.Script`), a network response (`http.get` / `https.request` / `axios.*` / `fetch(...)` → ... → `eval`), a dynamically-constructed / runtime-assembled string, or any other expression whose concrete value is not visible in the slice — and then hands it to `eval` / `new Function` / `vm.*`, or writes it to a file and `require`s / executes it. Network → eval and file → eval **without** an explicit decoding intermediary stay `undetermined` here; the decoding-intermediary case is the malicious upgrader (see the `"malicious"` definition above).

  In these cases, the handoff Node ID itself must go into both `key_evidence` and `node_to_be_checked` (its `node_type` follows the inline annotation: `third_party` / `unresolved` for bare slices; `third_party_with_metadata` only under the carve-out below), and the `reason` MUST identify the handoff target as concretely as the slice allows (resolved local path such as `<package>/app.js`, module identifier, or "code string assembled from `<source>`").
- The `reason` field **MUST** state what runtime info is needed.

### Type (f) resolvability rule *(enriched pass only)*
A third-party call annotated with module / API metadata should generally **NOT** remain `"undetermined"` unless **all three** of the following hold:
- The module operates in a security-sensitive domain (network, filesystem, process, system info), AND
- Sensitive data flows into or out of the call, AND
- The provided metadata is insufficient to determine intent.

If the module description indicates a non-sensitive domain (e.g., string utility, date library, math library), do **not** keep the node as undetermined.

### Type (f) control-flow handoff carve-out *(enriched pass only)*
The type-(f) resolvability rule above does **NOT** apply when the type-(f) call is itself a control-flow handoff to out-of-slice code (see the bullet above). The metadata resolves the **runner's** behavior (e.g., "PM2 starts a script"), not the **target's** behavior (what `./app.js` actually does at runtime). In this case the handoff Node ID stays in `node_to_be_checked` with `node_type: "third_party_with_metadata"`, even though the module domain ("process management" / "task runner") would otherwise look benign.

---

# Key Evidence Constraints

- **`"malicious"`**: `key_evidence` MUST include at least one critical Node ID proving the malicious behavior.
- **`"undetermined"`**: All nodes in `node_to_be_checked` MUST appear in `key_evidence`. These nodes MUST be of type `conditional_api`, `third_party`, or `unresolved` — **except** under the type-(f) control-flow handoff carve-out below, which is the only situation in which `third_party_with_metadata` is allowed there.
- **`"benign"`**: `key_evidence` should be empty or include at most 1–2 representative nodes.

## `node_to_be_checked` Type Whitelist (STRICT)
- ALLOWED node types: `conditional_api`, `third_party`, `unresolved`.
- FORBIDDEN node types (NEVER include): `sensitive_api`, `sensitive_property`, and — on the enriched pass — `third_party_with_metadata` outside the carve-out.
- Rationale: `sensitive_api` and `sensitive_property` already have fully resolved semantics from static analysis; `third_party_with_metadata` already carries enough context to decide statically. None of them can be meaningfully "checked" further at runtime — including them is a category error.
- A node that is statically resolved (including any `conditional_api` whose argument values are evident from the surrounding slice) belongs in `key_evidence` only, never in `node_to_be_checked`.
- **Carve-out — control-flow handoff to out-of-slice code** *(enriched pass only)*: a `third_party_with_metadata` node MAY appear in `node_to_be_checked` (with `node_type: "third_party_with_metadata"` in its matching `key_evidence` entry) **only** when it is the call site of a control-flow handoff to code outside the slice (see the `"undetermined"` definition — e.g., `pm2.start({ script: "./app.js" })`). The metadata describes the runner's behavior, not the launched target's behavior; the target remains unobservable from this slice and is what actually needs checking. This carve-out does NOT apply to ordinary type-(f) calls whose effects are self-contained (e.g., `axios.post(url, data)`); those continue to be forbidden from `node_to_be_checked`.

---

# Data-Flow Sanity
- Prefer judgements supported by a coherent source-to-sink story when the visible evidence permits.
- If a report or your own reasoning infers intent beyond what the visible evidence shows, downgrade to `"undetermined"` or `"benign"`.
- **Slice reachability invariant**: Slices are built along **both data flow and control flow**. A function body present in `sliced_code` is guaranteed to lie on a reachable control-flow path and **will execute at runtime** — even when its call site is absent from the slice (e.g., a zero-argument invocation contributes no data flow and may be pruned). Do **NOT** downgrade malicious-looking code to `"benign"` on a "function is defined but never called" / "dead code" basis; slicing has already ruled that out.

---

# False Positive Guardrails
Do **not** mark as malicious solely based on:
- Compatibility / environment checks using `os.*`, `process.*`, `process.env` with no outbound transmission
- Reads of local project / package metadata within normal scope
- Expected network behavior matching stated functionality without sensitive payload
- Safe-scope file writes to project / cache / temp without persistence or destructive intent
- A single sensitive API / property with no clear malicious chain
- **Known Non-Sensitive Third-Party Modules** *(applies only when type (f) annotations are present)* — third-party calls annotated with module descriptions that indicate non-sensitive functionality (e.g., string utilities, date libraries, math libraries, schema validators, color conversion utilities) should not be flagged as suspicious. Does **not** apply to handoff / runner modules even if their domain looks benign — see the type-(f) handoff carve-out above.
- Development-tooling behavior required for the package's own purpose, e.g. build tools / linters / bundlers / test runners / scaffolding CLIs spawning `node` / `npm` / `yarn` / `pnpm` / `git` / the package's own binary, or writing files under the project / package directory. When type (f) metadata is available and the module description corroborates a dev-tooling role, this guardrail is strengthened. Arguments must not be attacker-controlled (e.g. fetched from a remote URL or hardcoded suspicious payloads) for this guardrail to apply.
- **Legitimate native-binary usage** (overrides the "binary handoff = malicious" rule when the slice clearly matches one of these patterns):
  - Native Node.js addons loaded via `require()` of `.node` files under standard build paths (`./build/Release/`, `./build/Debug/`, `./prebuilds/<platform>/`, `./lib/binding/`, ...) or via the `bindings` / `node-pre-gyp` / `prebuild-install` / `node-gyp-build` helpers — this is the textbook layout for C/C++ addons (e.g. `sqlite3`, `sharp`, `bcrypt`, `fsevents`, `node-pty`).
  - FFI calls to standard platform shared libraries via `ffi-napi` / `koffi` / `node-ffi-napi` targeting system libs (`libc.so.*`, `kernel32.dll`, `user32.dll`, `libobjc.dylib`, ...) consistent with the package's stated purpose.
  - Bundled platform-specific helper binaries that are the package's **declared core functionality** and ship under a recognizable `npm`-platform layout (`@<scope>/<name>-<os>-<arch>` optional dependencies, `bin/<platform>/`, etc.) — e.g. `esbuild`, `@swc/core`, `turbo`, `@next/swc`, `rollup-plugin-*`, `vite` native deps.
  - Does **not** apply if the binary is fetched from a remote URL at install / runtime, written from an opaque buffer just before execution, lives outside the conventional addon / platform-package paths, or contradicts the package's declared functionality.
- Telemetry / diagnostic collection of **non-credential** system info (e.g. `os.type()`, `os.release()`, `process.version`, package version, error stack) when sent to an endpoint consistent with the package's stated purpose (confirmable via type (f) module / API metadata when present). Guardrail does **not** apply if the payload includes credentials, tokens, private files, environment variables at large, or the destination is a clearly suspicious / hardcoded IP / unrelated domain.
- Use of `crypto.*` (e.g. `createHash`, `createHmac`, `createCipheriv`, `randomBytes`, `sign/verify`) for legitimate purposes such as integrity checking, token signing, password hashing, or generating local identifiers — provided there is no evidence of encrypting an exfiltration payload or decrypting an externally fetched blob before executing it.
- `eval` / `new Function` / `vm.*` operating on **statically visible literal or locally-constructed** source that is consistent with the package's declared functionality (e.g. template engines compiling templates, expression evaluators, JSON-schema / query compilers, sandboxed plugin loaders; type (f) metadata describing such a role further supports this). Guardrail does **not** apply if the evaluated source comes from the network, `Buffer.from(..., 'base64')` of an opaque blob, obfuscated strings, or other untrusted / hidden sources.
- **Opaque-source `eval`**: when the executed source string is **not statically determinable** from the visible slice (the argument is a non-literal variable, a return value, a file / network read, or any other expression whose concrete value the slice does not show), **prefer `"undetermined"` over `"malicious"` even when the surrounding slice also contains highly suspicious behaviors** on adjacent Node IDs (sensitive file / env reads, outbound network calls, hardcoded suspicious URLs, credential-shaped strings, child-process spawns, etc.). Static analysis cannot prove that the eval node actually executes the malicious payload without observing the concrete source string — co-occurrence with suspicious patterns is **suspicion, not proof**. A definitive `"malicious"` requires either (i) the eval source string itself, or (ii) a directly-traceable construction of it from values present in the slice, to be visible. Otherwise route the eval node for runtime resolution and include it in `node_to_be_checked`.
  - **Exception — decoding intermediary**: this guardrail does **NOT** apply when the slice shows the opaque source flowing through an explicit decode / deobfuscation step (`Buffer.from(..., 'base64').toString()`, `atob(...)`, hex / `\xNN` / `\uXXXX` decoding, `String.fromCharCode(...)` reassembly, split-join character tricks, ROT-N / XOR / custom stream decoders, etc.) before reaching `eval` / `Function` / `vm.*`. The decoding intermediary itself constitutes the missing proof — legitimate eval consumers do not need to deobfuscate their own input. In that case, mark `"malicious"` and cite both the decode-site Node ID and the eval-site Node ID in `key_evidence`. All other opaque-source cases (network read directly → eval, file read directly → eval, plain variable → eval, runtime-constructed string → eval) continue to default to `"undetermined"` per the rule above.

---

# Conflict Resolution Policy
- **When in doubt, choose `"undetermined"` rather than `"malicious"`.**
- **Type-(f) preference** *(enriched pass only)*: if reports disagree on whether a type-(f) node should be undetermined, prefer resolving it using the metadata context rather than deferring to dynamic analysis. The whole point of enrichment is to drain such ambiguity from third-party calls whose module / API description already explains them.
- **Out-of-slice handoff override**: when the slice exhibits a control-flow handoff to code that is not in the slice (process / worker spawn of a local script, process-manager registration, `readFile` → `eval` / `Function` / `vm.*`, etc.), **prefer `"undetermined"` over `"benign"` even when the call site itself looks textbook-standard.** A "benign-looking" wrapping (postinstall hook, package-local target path, well-known process manager / loader, prior-context shell label of `benign`) does not vouch for the launched target's behavior; only inspecting the target itself can. Route the handoff Node ID into `key_evidence` + `node_to_be_checked` so the target can be analyzed downstream. A definitive `"benign"` is only appropriate when the launched target's behavior is itself visible (in the slice / `callee_info`, or in the read-file contents when present) and is itself benign.
- **Handoff override beats the type-(f) resolvability rule**: even when the handoff call site is itself a type-(f) annotation and its module domain (e.g., "process manager", "task runner") looks benign, the metadata only resolves the runner's behavior, not the target's. Route the handoff Node ID into `key_evidence` + `node_to_be_checked` (with `node_type: "third_party_with_metadata"` under the carve-out) so the target can be analyzed downstream.

The header section above may declare additional mode-specific conflict-resolution rules (e.g. how to weight three first-stage reports in verify mode, or how to upgrade / downgrade the prior verdict in reread mode). Apply those *on top of* the rules in this section.

---

# Base Output Schema
Output must be a **single JSON object** with exactly the following keys:
```json
{
  "judgement": "benign" | "malicious" | "undetermined",
  "key_evidence": [
    {
      "node_id": number,
      "node_type": "sensitive_api" | "conditional_api" | "third_party" | "third_party_with_metadata" | "unresolved" | "sensitive_property",
      "claim": string
    }
  ],
  "reason": string,
  "node_to_be_checked": number[],
  "files_to_read": string[]
}
```
- This object is the final report — do not output any prior reports.
- Do not add extra keys beyond those listed here.
- Use `"third_party_with_metadata"` **only** for nodes that carry a type (f) annotation in the slice. On the bare pass, this value must not appear at all.
- Ensure JSON is syntactically valid.

## `files_to_read` — request package-local files for re-judgement
Use this field to ask the orchestrator to fetch the **package-local source** of files whose behaviour is not visible in the current `sliced_code` / `callee_info` (or, in reread mode, in the `read_files` already provided) but is essential to your judgement. The orchestrator will resolve each path, read the body, run a binary-vs-script classification, and re-invoke this verifier in **reread mode** with your prior report + the read file contents so the verdict can be reconciled.

When to populate `files_to_read`:
- The slice contains a **control-flow handoff to a local script or local source file** that is not present in `sliced_code` / `callee_info`. Patterns like: `path.join(__dirname, ..., 'autorun.bat' | 'start.sh' | 'cli.js' | ...)` passed to `child_process.spawn` / `exec*` / `fork`, `cluster.fork`, `new Worker(...)`, `pm2.start({ script })`, `forever.start(...)`, `nodemon(...)`, `fs.readFile(localPath)` → `eval` / `new Function` / `vm.*`, dynamic `require('./...')` / `import('./...')`.
- A `third_party` / `third_party_with_metadata` / `unresolved` node in `key_evidence` actually resolves to a package-local file (e.g. an inline `require('./loader')`) and you need its body to judge.
- A `conditional_api` node depends on values produced by another local file referenced in the slice.
- (Reread mode) A read file you already received contains a *further* handoff to a different package-local file you do not yet have.

Rules for the paths you put in `files_to_read`:
- Each entry MUST be a **package-relative** path (e.g. `bin/autorun.bat`, `lib/foo.js`, `./scripts/start.sh`). Leading `./` is accepted.
- Never put bare specifiers (`axios`, `lodash`, `fs`, `@scope/pkg`), absolute paths, or paths that escape the package root.
- Include native binaries (`.exe` / `.dll` / `.so` / `.dylib` / `.bin` / `.node` / extensionless ELF / Mach-O / PE) when they are the spawn target — the orchestrator detects them up front and **immediately finalizes the verdict as `malicious`** without reading their bodies or calling the LLM again, so you do not have to special-case binaries yourself.
- Include shell / standalone scripts (`.sh` / `.bat` / `.ps1` / `.py` / `.pl` / `.rb`) and JS / JSON files (`.js` / `.cjs` / `.mjs` / `.json`) whose body you would judge if you could read it.
- **Do not re-request files already present in the `read_files` array** (reread mode) — those bodies are already in your context.
- Leave `files_to_read: []` when nothing local needs to be inspected. **An empty list is the correct answer for the vast majority of slices.**
- Cap: at most 6 paths per call.

`files_to_read` does NOT replace `node_to_be_checked`. When `judgement == "undetermined"`, you must still populate `node_to_be_checked` per the rules above; `files_to_read` is an *additional* request the orchestrator may grant.

The header section above may declare **additional constraints** on `files_to_read` (e.g. a hop-budget cap in reread mode that forces `files_to_read: []` on the final hop). Apply those on top of the rules in this section.

## Consistency Hardening
- If `judgement` is `"undetermined"` → `node_to_be_checked` must be **non-empty**.
- If `judgement` is not `"undetermined"` → `node_to_be_checked` must be `[]`.
- `files_to_read` may be non-empty regardless of `judgement` (e.g. a `benign`-looking spawn of `./bin/autorun.bat` should still request the script for confirmation) — *subject to* any header-imposed hop budget.

## Final Self-Check (perform silently before emitting the JSON)
1. For every Node ID in `node_to_be_checked`, locate the matching entry in `key_evidence` and confirm its `node_type` is one of `conditional_api`, `third_party`, `unresolved`. If any entry is `sensitive_api` or `sensitive_property`, **remove that Node ID** from `node_to_be_checked`. If the entry is `third_party_with_metadata`, remove it **unless** the corresponding code site is a control-flow handoff to out-of-slice code (see the `"undetermined"` definition and the whitelist carve-out) — in that single case, keep it.
2. If, after step 1, `judgement == "undetermined"` but `node_to_be_checked` ends up empty, downgrade `judgement` to `"benign"` (since no truly unresolved node remains).
3. If `judgement` is `"benign"` or `"malicious"`, ensure `node_to_be_checked` is `[]`.
4. Ensure `files_to_read` is a JSON array of strings (possibly empty). Drop any duplicates, any entries that are not package-relative paths, and (reread mode) any path already present in `read_files`.
5. If the bare pass is active (no type (f) annotation present in the slice), ensure no `key_evidence` entry uses `node_type: "third_party_with_metadata"`. Rewrite any such entries to `"third_party"` or drop them.
6. Apply any additional mode-specific self-check items declared in the header above (e.g. enforcing the hop budget in reread mode).
