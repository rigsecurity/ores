# :material-web-box: WASM Guide

The `ores.wasm` module is a WASI preview 1 binary that embeds the complete ORES engine. It runs in any WASI-capable runtime — wasmtime, wasmer, Node.js, Python, Deno, and more.

The module follows a simple **stdin/stdout protocol**: send a JSON `EvaluationRequest` to stdin, receive a JSON `EvaluationResult` from stdout. No network, no filesystem access.

---

## Download

The `ores.wasm` file is attached to every [GitHub release](https://github.com/rigsecurity/ores/releases):

```bash
curl -Lo ores.wasm \
  https://github.com/rigsecurity/ores/releases/latest/download/ores.wasm
```

??? note "Building from source"
    Requires Go 1.25 and the [Task](https://taskfile.dev/) task runner.

    ```bash
    git clone https://github.com/rigsecurity/ores.git
    cd ores
    task build:wasm
    # Output: bin/ores.wasm
    ```

    Or build directly with `go build`:

    ```bash
    GOOS=wasip1 GOARCH=wasm go build -o bin/ores.wasm ./pkg/wasm
    ```

---

## stdin/stdout Protocol

The WASM module is a pure function over standard I/O:

| Stream | Content |
|--------|---------|
| **stdin** | A single JSON `EvaluationRequest` object |
| **stdout** | A JSON `EvaluationResult` object on success |
| **stderr** | A JSON error object on failure: `{"error": "<message>"}` |
| **Exit code** | `0` on success, `1` on error |

!!! info "Zero capabilities required"
    The module does not make network calls, does not access the filesystem (beyond stdio), and does not require any WASI capabilities beyond standard I/O streams. This makes it safe to run in any sandboxed environment.

---

## Runtime Examples

=== ":material-console: wasmtime"

    Install wasmtime:

    ```bash
    # macOS / Linux
    curl https://wasmtime.dev/install.sh -sSf | bash
    # or
    brew install wasmtime
    ```

    Run an evaluation:

    ```bash
    echo '{
      "apiVersion": "ores.dev/v1",
      "kind": "EvaluationRequest",
      "signals": {
        "cvss": { "base_score": 9.8 },
        "epss": { "probability": 0.91, "percentile": 0.98 },
        "threat_intel": { "actively_exploited": true }
      }
    }' | wasmtime ores.wasm
    ```

    Output:

    ```json
    {
      "apiVersion": "ores.dev/v1",
      "kind": "EvaluationResult",
      "score": 79,
      "label": "high",
      "version": "0.1.0-preview",
      "explanation": {
        "signals_provided": 3,
        "signals_used": 3,
        "signals_unknown": 0,
        "unknown_signals": [],
        "warnings": [],
        "confidence": 0.55,
        "factors": [...]
      }
    }
    ```

    Error handling:

    ```bash
    echo '{}' | wasmtime ores.wasm
    # stderr: {"error":"invalid request: apiVersion is required"}
    # exit code: 1
    ```

=== ":material-nodejs: Node.js"

    **Option 1: Native WASI bindings**

    ```bash
    npm install @bytecodealliance/wasmtime
    ```

    ```javascript
    const { Engine, Module, Store, WasiCtx } = require('@bytecodealliance/wasmtime');
    const { readFileSync } = require('fs');

    async function scoreVulnerability(signals) {
      const wasmBytes = readFileSync('./ores.wasm');

      const engine = new Engine();
      const module = new Module(engine, wasmBytes);
      const store = new Store(engine);

      const request = JSON.stringify({
        apiVersion: 'ores.dev/v1',
        kind: 'EvaluationRequest',
        signals,
      });

      const inputBytes = Buffer.from(request, 'utf-8');

      const wasi = new WasiCtx({
        args: ['ores'],
        env: {},
        stdin: inputBytes,
      });

      const linker = wasi.linker(store);
      const instance = await linker.instantiate(store, module);

      wasi.startExecution(store, instance);

      const output = wasi.stdout;
      return JSON.parse(output.toString('utf-8'));
    }

    // Usage
    scoreVulnerability({
      cvss: { base_score: 9.8 },
      epss: { probability: 0.91, percentile: 0.98 },
      threat_intel: { actively_exploited: true },
      asset: { criticality: 'high', network_exposure: true },
    }).then(result => {
      console.log(`Score: ${result.score} (${result.label})`);
      console.log(`Confidence: ${result.explanation.confidence}`);
    });
    ```

    **Option 2: Simple subprocess** (for scripts and tools)

    ```javascript
    const { execFileSync } = require('child_process');

    function scoreVulnerability(signals) {
      const input = JSON.stringify({
        apiVersion: 'ores.dev/v1',
        kind: 'EvaluationRequest',
        signals,
      });

      const output = execFileSync('wasmtime', ['./ores.wasm'], {
        input,
        encoding: 'utf-8',
      });

      return JSON.parse(output);
    }

    const result = scoreVulnerability({
      cvss: { base_score: 7.5 },
      nist: { severity: 'high' },
    });

    console.log(result.score, result.label);
    ```

    !!! tip "Which approach to choose?"
        Use **native WASI bindings** when you need to avoid spawning subprocesses (serverless, web workers, embedded contexts). Use the **subprocess approach** for CLI tools and scripts where simplicity matters more than startup latency.

=== ":material-language-python: Python"

    **Option 1: Native wasmtime bindings**

    ```bash
    pip install wasmtime
    ```

    ```python
    import json
    from wasmtime import (
        Engine, Module, Store, Linker,
        WasiConfig, Config
    )

    def score_vulnerability(signals: dict) -> dict:
        """Score a vulnerability using the ORES WASM module."""
        request = json.dumps({
            "apiVersion": "ores.dev/v1",
            "kind": "EvaluationRequest",
            "signals": signals,
        })

        config = Config()
        engine = Engine(config)
        store = Store(engine)

        wasi_config = WasiConfig()
        wasi_config.stdin_bytes(request.encode("utf-8"))

        # Capture stdout into a temporary file
        output_path = "/tmp/ores_output.json"
        wasi_config.stdout_file(output_path)

        store.set_wasi(wasi_config)

        linker = Linker(engine)
        linker.define_wasi()

        with open("ores.wasm", "rb") as f:
            wasm_bytes = f.read()

        module = Module(engine, wasm_bytes)
        instance = linker.instantiate(store, module)

        start = instance.exports(store)["_start"]
        start(store)

        with open(output_path, "r") as f:
            return json.load(f)


    # Usage
    result = score_vulnerability({
        "cvss": {"base_score": 9.8},
        "epss": {"probability": 0.91, "percentile": 0.98},
        "threat_intel": {"actively_exploited": True},
        "asset": {
            "criticality": "high",
            "network_exposure": True,
            "data_classification": "pii",
        },
    })

    print(f"Score: {result['score']} ({result['label']})")
    print(f"Confidence: {result['explanation']['confidence']}")
    for factor in result["explanation"]["factors"]:
        print(f"  {factor['factor']}: +{factor['contribution']}")
    ```

    **Option 2: Simple subprocess**

    ```python
    import json
    import subprocess

    def score_vulnerability(signals: dict) -> dict:
        request = json.dumps({
            "apiVersion": "ores.dev/v1",
            "kind": "EvaluationRequest",
            "signals": signals,
        })

        result = subprocess.run(
            ["wasmtime", "ores.wasm"],
            input=request.encode("utf-8"),
            capture_output=True,
            check=True,
        )

        return json.loads(result.stdout)


    result = score_vulnerability({"cvss": {"base_score": 7.5}})
    print(result["score"], result["label"])
    ```

    !!! tip "Module reuse in Python"
        When scoring many vulnerabilities in a loop, compile the `Module` once outside the function and pass it in. This avoids re-reading and re-compiling the `.wasm` file on each call.

---

## :material-lightning-bolt: Performance Tips

### Pre-compile with wasmtime AOT

Wasmtime supports ahead-of-time compilation to a `.cwasm` file, eliminating compilation overhead on repeated cold starts:

```bash
# Compile once
wasmtime compile ores.wasm -o ores.cwasm

# Run the pre-compiled version (sub-millisecond startup)
echo '...' | wasmtime run --allow-precompiled ores.cwasm
```

### Reuse the Module object

When using the wasmtime API directly (Go, Node.js, Python), compile the `Module` once and reuse it across evaluations. Module compilation is the most expensive step.

```python
# Do this once
module = Module(engine, wasm_bytes)

# Reuse for every evaluation
for signals in vulnerability_list:
    store = Store(engine)
    # ... instantiate with the same module
```

### When to use the daemon instead

If you need to score **thousands of vulnerabilities per second**, the [`oresd` daemon](daemon.md) is the better choice. It amortizes engine initialization across all requests and provides health checks, audit logging, and gRPC support.

| Use case | Recommended approach |
|----------|---------------------|
| CI pipelines, scripting | WASM via wasmtime CLI |
| Serverless functions, edge compute | WASM via native bindings |
| Browser or web worker | WASM via native bindings |
| High-throughput backend service | `oresd` daemon |
| In-process Go application | [Go library](library.md) |

!!! warning "Startup time"
    The WASM module starts up in **under 10 ms** on modern hardware with wasmtime. However, this cost is paid on every invocation when using the CLI approach. For latency-sensitive paths, use native bindings with module reuse or switch to the daemon.
