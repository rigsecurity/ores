# WASM Guide

The `ores.wasm` module is a WASI preview1 binary that embeds the complete ORES engine. It runs in any WASI-capable runtime: wasmtime, wasmer, Node.js (via the `@bytecodealliance/jco` or wasmtime packages), Python, Deno, and more.

The WASM module follows a simple stdin/stdout protocol: send a JSON `EvaluationRequest` to stdin and receive a JSON `EvaluationResult` from stdout. No network, no filesystem access.

---

## Download

The `ores.wasm` file is attached to every [GitHub release](https://github.com/rigsecurity/ores/releases):

```bash
curl -Lo ores.wasm https://github.com/rigsecurity/ores/releases/latest/download/ores.wasm
```

---

## Building from Source

Requires Go 1.25 and the [Task](https://taskfile.dev/) task runner.

```bash
git clone https://github.com/rigsecurity/ores.git
cd ores
task build:wasm
# Output: bin/ores.wasm
```

The build uses `GOOS=wasip1 GOARCH=wasm`:

```bash
GOOS=wasip1 GOARCH=wasm go build -o bin/ores.wasm ./pkg/wasm
```

---

## Running with wasmtime

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

---

## stdin/stdout Protocol

The WASM module is a pure function over stdin/stdout:

- **stdin**: A single JSON `EvaluationRequest` object (see [Signals](../concepts/signals.md) for the full schema)
- **stdout**: A JSON `EvaluationResult` object on success
- **stderr**: A JSON error object on failure: `{"error": "<message>"}`
- **Exit code**: `0` on success, `1` on error

The module does not make any network calls, does not access the filesystem (beyond stdin/stdout/stderr), and does not require WASI capabilities beyond the standard I/O streams.

### Error output example

```bash
echo '{}' | wasmtime ores.wasm
# stderr: {"error":"invalid request: apiVersion is required"}
# exit code: 1
```

---

## Node.js Integration

Install the wasmtime Node.js package:

```bash
npm install @bytecodealliance/wasmtime
```

```javascript
const { Engine, Module, Store, Instance, Memory, WasiCtx } = require('@bytecodealliance/wasmtime');
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

### Simpler approach with child_process

For scripts and tools where spawning a subprocess is acceptable:

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

---

## Python Integration

Install the Python wasmtime package:

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

    # Capture stdout into a byte buffer
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
for factor in result['explanation']['factors']:
    print(f"  {factor['factor']}: +{factor['contribution']}")
```

### Simpler subprocess approach

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

---

## Performance Considerations

The WASM module starts up in under 10ms on modern hardware using wasmtime's ahead-of-time (AOT) compilation. For high-throughput use cases, consider:

1. **Use the daemon instead**: If you need to score thousands of vulnerabilities per second, the `oresd` daemon is the better choice. It amortizes the engine initialization cost across all requests.
2. **Reuse the wasmtime instance**: When using the Go, Node.js, or Python APIs directly, compile the module once and reuse the `Module` object across evaluations.
3. **Pre-compile with wasmtime**: Wasmtime supports ahead-of-time compilation to a `.cwasm` file, eliminating compilation overhead on repeated cold starts.

```bash
# Pre-compile to AOT format
wasmtime compile ores.wasm -o ores.cwasm

# Run the pre-compiled version
echo '...' | wasmtime run --allow-precompiled ores.cwasm
```
