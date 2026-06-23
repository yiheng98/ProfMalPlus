# Judgement Definitions

## `"benign"`
Use when:
- The runtime evidence (plus any read file content provided by the header above) shows common, legitimate behaviour.
- Sensitive APIs / properties (annotation types **(a)**, **(b)**, **(h)**, **(i)**) appear in expected contexts and any resolved arguments are non-malicious.
- Third-party / previously-unresolved behaviour descriptions (types **(d)**, **(f)**, **(h)**) describe legitimate functionality consistent with the package's stated purpose.
- No clear malicious data flow is supported by the visible runtime evidence.

## `"malicious"`
Use **ONLY** when the malicious behaviour is **definitive** from the runtime evidence alone (plus any read file content provided by the header above). You can point to specific Node IDs whose **resolved arguments** / **return values** / **behavior descriptions** clearly prove malicious intent or behaviour, such as:
- Reading sensitive system / credential files (e.g., `/etc/passwd`, `~/.ssh/*`, env-derived tokens) and sending them to an external endpoint
- Executing hardcoded or clearly malicious commands
- Downloading and executing a remote payload (the runtime trace shows the download AND the subsequent execution of the dropped artefact)
- Destructive file / system operations
- Obvious backdoor / reverse-shell logic
- **Opaque external process execution — native binary**: the slice spawns a package-bundled **native binary** (`.exe` / `.dll` / `.so` / `.dylib` / `.bin` / `.node` or an extensionless ELF / Mach-O / PE) via `child_process.exec*` / `spawn*` / `fork`, `execa`, `cross-spawn`, `shelljs.exec`, etc., and **no** type (d) / (f) / (h) behavior description captures what the subprocess does. The dynamic phase cannot trace into compiled artefacts, so treat them as malicious by default. Cite the spawning Node ID and resolved target; the dev-tooling allowlist below is the only exception. **Standalone text scripts (`.sh` / `.bat` / `.ps1` / `.py` / `.pl` / `.rb`) and local JS / JSON files do NOT fall under this rule** — for those, request the file via `files_to_read` so the orchestrator can fetch the script body for the next reread hop.

The `explanation` **MUST** name the critical Node IDs and the runtime values that make the behaviour malicious.

Hedged behaviour descriptions ("appears to", "likely", "may") in type (h) annotations are **insufficient on their own** — combine with another concrete piece of evidence (resolved argument, file_io_record, behaviour description without hedging) before concluding malicious.

## `"undetermined"`
Use when suspicious patterns exist but final intent depends on data the runtime evidence does not resolve, e.g.:
- A `large_text` file central to the data flow whose content is unknown — either because it was skipped from `file_inspections` (no matching entry) or because the available `content_summary` / `security_signals` are themselves ambiguous.
- A behavior description for type (d), (f), or (h) that is genuinely ambiguous.
- An unresolved call (type g) sitting on a sensitive data path.
- A local script / JS file referenced by a spawn / fork / require whose body is not yet present in `read_files` (when invoked in reread mode).

The `explanation` **MUST** state what specific runtime evidence (or which package-local file) is still missing.

---

# Data-Flow Sanity
- Prefer judgements supported by a coherent **source-to-sink** story validated by resolved runtime arguments, behavior descriptions, `file_io_records`, and any matching `file_inspections`.
- If the report (or your reasoning) infers intent beyond what the runtime + inspection evidence shows, downgrade to `"undetermined"` or `"benign"`.
- Do **not** rewrite hedged evidence (annotations marked with "appears to", "likely", "may", or annotations recovered via async-attribution heuristics) as fact in the verified `explanation`.
- An empty `security_signals` array on a `file_inspections` entry that is central to the suspicion is a strong **negative** signal: do not maintain a malicious verdict against that file without independent runtime evidence.
- **Slice reachability invariant**: Slices are built along **both data flow and control flow**. A function body present in `sliced_code` is guaranteed to lie on a reachable control-flow path and **will execute at runtime** — even when its call site is absent from the slice (e.g., a zero-argument invocation contributes no data flow and may be pruned). Do **NOT** downgrade malicious-looking code to `"benign"` on a "function is defined but never called" / "dead code" basis; slicing has already ruled that out. Absence of a runtime annotation on the call site only means the harness did not happen to exercise it under this run, not that the code is unreachable.

---

# False Positive Guardrails
Do **not** mark as malicious solely based on:
- Compatibility / environment checks using `os.*`, `process.*`, `process.env` with no outbound transmission of the read values
- Reads of local project / package metadata within normal scope (e.g., `package.json`, README, lockfiles)
- Expected network behaviour matching the package's stated functionality, with no sensitive data in the resolved request payload
- Safe-scope file writes to project / cache / temp directories (project root, the installed package directory, `os.tmpdir()`, library-returned user-config dirs) without persistence or destructive intent
- A single sensitive API / property with no clear malicious chain in the runtime trace
- Development-tooling behaviour required for the package's own purpose: build tools / linters / bundlers / test runners / scaffolding CLIs spawning standard Node.js ecosystem CLIs (`node` / `npm` / `npx` / `yarn` / `pnpm` / `tsc` / `babel` / `webpack` / `vite` / `jest` / `eslint` / `prettier`), `git`, or common POSIX utilities, or writing files under the project / package directory. Resolved arguments must not be attacker-controlled (remote URL, opaque blob, hardcoded suspicious payload). **This guardrail does NOT cover package-bundled native binaries; those fall under the opaque-binary-subprocess malicious rule even when bundled with the package itself. Package-bundled standalone text scripts (`.sh` / `.bat` / `.ps1` / `.py` / etc.) are handled by the reread loop — request them via `files_to_read` rather than relying on this guardrail.**
- **Legitimate native-binary usage** (overrides the "opaque native-binary spawn = malicious" rule when the slice clearly matches one of these patterns):
  - Native Node.js addons loaded via `require()` of `.node` files under standard build paths (`./build/Release/`, `./build/Debug/`, `./prebuilds/<platform>/`, `./lib/binding/`, ...) or via the `bindings` / `node-pre-gyp` / `prebuild-install` / `node-gyp-build` helpers (e.g. `sqlite3`, `sharp`, `bcrypt`, `fsevents`, `node-pty`).
  - FFI calls to standard platform shared libraries via `ffi-napi` / `koffi` / `node-ffi-napi` targeting system libs (`libc.so.*`, `kernel32.dll`, `user32.dll`, `libobjc.dylib`, ...) consistent with the package's stated purpose.
  - Bundled platform-specific helper binaries that are the package's **declared core functionality** and ship under a recognizable `npm`-platform layout (`@<scope>/<name>-<os>-<arch>` optional dependencies, `bin/<platform>/`, etc.) — e.g. `esbuild`, `@swc/core`, `turbo`, `@next/swc`, `rollup-plugin-*`, `vite` native deps.
  - Does **not** apply if the binary is fetched from a remote URL at install / runtime, written from an opaque buffer just before execution, lives outside the conventional addon / platform-package paths, or contradicts the package's declared functionality.
- Telemetry / diagnostic collection of **non-credential** system info (e.g., `os.type()`, `os.release()`, `process.version`, package version, error stack) when the resolved destination URL is consistent with the package's stated purpose. Guardrail does **not** apply if the resolved payload includes credentials, tokens, private files, environment variables at large, or the destination is a clearly suspicious / hardcoded IP or unrelated domain.
- Use of `crypto.*` (e.g., `createHash`, `createHmac`, `createCipheriv`, `randomBytes`, `sign` / `verify`) for legitimate purposes such as integrity checking, token signing, password hashing, or generating local identifiers — provided the runtime trace shows no encryption of an exfiltration payload nor decryption of an externally fetched blob immediately before executing it.
- `eval` whose **dynamically resolved source argument** (annotation type **(k)** — backtick-quoted preview(s) following `resolved eval source argument(s):`) is a literal or locally-constructed string consistent with the package's declared functionality (template engines, expression evaluators, JSON-schema / query compilers, sandboxed plugin loaders). Inspect the preview content directly when applying this guardrail. Guardrail does **not** apply if the resolved source — or the inspected content of the file from which that source was loaded (visible via `file_inspections.content_summary` / `security_signals`) — comes from the network, a `Buffer.from(..., 'base64')` decode of an opaque blob, an obfuscated string, or any other untrusted / hidden source.
- **Unresolved-source `eval`** *(dynamic side only)*: when an `eval` / `new Function` / `vm.*` site appears in the slice but the runtime trace did **NOT** emit a type **(k)** "resolved eval source argument(s)" annotation for it (the eval did not fire under the harness, or fired without the source argument being captured), do **not** default to `"undetermined"`. Inspect the slice and the surrounding runtime trace around the eval site:
  - **Lean `"malicious"`** when the trace shows an explicit decoding / deobfuscation step (`Buffer.from(..., 'base64').toString()`, `atob(...)`, hex / `\xNN` / `\uXXXX` decoding, `String.fromCharCode(...)` reassembly, split-join character tricks, ROT-N / XOR / custom stream decoders, etc.), a network fetch (`http.*` / `https.*` / `axios.*` / `fetch(...)` resolved to a non-package endpoint), or an opaque buffer / `large_text` `file_inspections` entry feeding into the eval input. Cite both the suspicious intermediary Node ID and the eval-site Node ID in `explanation`.
  - **Lean `"benign"`** otherwise — when the eval input has no visible decoding / network / opaque-buffer provenance in the trace, even if other unrelated sensitive APIs co-occur in the slice. Static co-occurrence of unrelated sensitive APIs is *not* sufficient to justify `"undetermined"` here; this dynamic-only relaxation explicitly trades a small amount of recall for a meaningful reduction in false positives (the static side keeps `"undetermined"` as its default for opaque-source eval — see Conflict Resolution below).

---

# Conflict Resolution Policy
- If a node-grounded runtime evidence chain supports the verdict and respects the false-positive guardrails → keep it.
- If the prior report (in verify mode) over-claims malicious intent without runtime-grounded evidence → downgrade to `"undetermined"` or `"benign"`.
- If the prior report misses a clear malicious pattern visible in the runtime trace → upgrade to `"malicious"` and cite the supporting Node IDs in `explanation`.
- If an **opaque native-binary spawn** is left as `"benign"` or `"undetermined"` (no type (d) / (f) / (h) behavior description for the subprocess, target classified as a native binary, outside the dev-tooling allowlist) → upgrade to `"malicious"` and cite the spawning Node ID and resolved binary path.
- If an **opaque script / local-file handoff** (`.sh` / `.bat` / `.ps1` / `.py` / `.js` / etc. inside the package, no runtime behavior description for the launched target) is left as `"benign"`, downgrade to `"undetermined"` and emit the target path(s) in `files_to_read` so the orchestrator can fetch the body for the next reread hop.
- If an **`eval` site has no type (k) resolved source annotation** and the runtime trace shows **no decoding / network / opaque-buffer feed** into it → prefer `"benign"` over `"undetermined"` (mirrors the Unresolved-source `eval` guardrail above). This is a dynamic-only relaxation aimed at reducing false positives; the static verifier keeps `"undetermined"` as its default for opaque-source eval. Conversely, if such a feed *is* visible in the trace, upgrade the eval site to `"malicious"` and cite both the intermediary and eval Node IDs.
- **When in doubt, choose `"undetermined"` rather than `"malicious"`** — except for opaque-native-binary cases, where "we cannot see what the binary does" is itself the decision criterion, and except for the unresolved-source `eval` case above, where the dynamic policy prefers `"benign"` to reduce false positives.

The header section above may declare additional mode-specific conflict-resolution rules (e.g. how to weight the judger's prior report in verify mode, or how to upgrade / downgrade the prior verdict in reread mode given the newly read file contents). Apply those *on top of* the rules in this section.

---

# Base Output Schema
Output must be a **single JSON object** with exactly the following keys:
```json
{
  "judgement": "benign | malicious | undetermined",
  "explanation": "1-3 sentence reasoning citing the relevant Node IDs, resolved runtime values, and any supporting file_inspections / read-file entries.",
  "files_to_read": ["<package-relative path 1>", "<path 2>"]
}
```
- This object is the final report — do not output any prior reports.
- Do not add extra keys beyond those listed here.
- Ensure JSON is syntactically valid.

## `files_to_read` — request package-local files for re-judgement
Use this field to ask the orchestrator to fetch the **package-local source** of files whose behaviour the runtime trace did **not** capture (or, in reread mode, whose body is still missing after the current `read_files`). The orchestrator will resolve each path, classify it (binary vs script), short-circuit native binaries to `malicious` *without* any further LLM call, and otherwise read the script body and re-invoke this verifier in **reread mode** with the prior report + accumulated read file contents.

When to populate `files_to_read`:
- A `file_io_records` entry points at a package-local path with `content_tier == "large_text"` but is **absent** from `file_inspections` (cap-skipped or runtime read failed) — request that path.
- A `require()` annotation (type **(j)**) imports a local relative path and no behavior description / file inspection covers what the loaded module actually did at runtime — request the target file.
- The slice spawns a long-running service (`child_process.spawn('node', ['./x.js'])`, `fork('./worker.js')`, `cluster.fork`, `new Worker('./worker.js')`, `express()` / `fastify()` / `http.createServer()` + `.listen(...)` plus `require('./routes')`, `pm2.start({ script: './x' })`, `forever.start('./x')`, `nodemon('./x')`) and the launched local script's behaviour is not visible in the runtime annotations — request the launched script (and the route / handler files it `require`s, up to the cap).
- The slice spawns a package-bundled **text script** (`.sh` / `.bat` / `.ps1` / `.py` / etc.) — request it so the orchestrator can read the script body. (Native binaries are also acceptable here: the orchestrator finalises `malicious` upstream without invoking the reread LLM.)
- (Reread mode) A previously-read file in `read_files` itself contains a **further** handoff to a different package-local file you do not yet have.

Rules for the paths you put in `files_to_read`:
- Each entry MUST be a **package-relative** path (e.g. `bin/autorun.bat`, `routes/auth.js`). Leading `./` is accepted.
- Never put bare specifiers (`axios`, `lodash`, `fs`, `@scope/pkg`), absolute paths, or paths that escape the package root.
- **Do not re-request files already present in the `read_files` array** (reread mode) — those bodies are already in your context.
- Cap: at most 6 paths per call. Pick the ones that would most change the verdict.
- Leave `files_to_read: []` when the runtime evidence + file_inspections + already-read files already cover everything material.

The header section above may declare **additional constraints** on `files_to_read` (e.g. a hop-budget cap in reread mode that forces `files_to_read: []` on the final hop). Apply those on top of the rules in this section.

## Consistency Hardening
- `files_to_read` may be non-empty regardless of `judgement` (e.g. a `benign`-looking spawn of `./bin/autorun.bat` should still request the script for confirmation) — *subject to* any header-imposed hop budget.

## Final Self-Check (perform silently before emitting the JSON)
1. Ensure `judgement` is exactly one of `"benign"` / `"malicious"` / `"undetermined"`.
2. Ensure `explanation` is a non-empty string of 1–3 sentences and references concrete Node IDs / resolved values / file inspections / read-file content where applicable.
3. Ensure `files_to_read` is a JSON array of strings (possibly empty). Drop any duplicates, any entries that are not package-relative paths, and (reread mode) any path already present in `read_files`.
4. Apply any additional mode-specific self-check items declared in the header above (e.g. enforcing the hop budget in reread mode).
