# Running research code on UDCS: the `udcs` client

> **Current status:** running your own code is **turned off** on every UDCS deployment until the lab-image security review and the administrator node-eligibility controls are complete ([ADR 0001](../decisions/0001-workload-isolation.md), [ADR 0002](../decisions/0002-user-code-packaging.md)).
>
> **What works today:**
> - You can prepare a project, validate it against the deployment, and upload and register it. Registering means the controller checks it as well.
> - The built-in catalog jobs run normally.
>
> `udcs submit` tells you plainly when no job was created.

## 1. Log in

```
udcs login --server https://udcs.your-university.edu
```

**How the password and session are handled:**
- The password is read from a hidden prompt only, never from a flag or an environment variable.
- The session token is bound to that server and expires after the deployment's session lifetime (12 h by default).
- **Windows:** it is stored encrypted with DPAPI for your Windows account (`%APPDATA%\udcs\session`).
- **Elsewhere:** it is stored in a file only you can read (`~/.config/udcs/session`).

**Campus CA.** If your campus uses its own certificate authority, add `--ca-bundle campus-ca.pem` once; it is remembered.

**Other commands:** `udcs whoami` shows who you are logged in as; `udcs logout` revokes the session.

## 2. Create or select a project

```
udcs init my-analysis          # writes my-analysis/udcs.toml and my-analysis/main.py
cd my-analysis
```

**Selecting a project:** every command acts on the nearest `udcs.toml` (searching upward from the current directory), or on `-C DIR`.

**An example `udcs.toml`:**

```toml
[project]
name = "protein-fold"
version = "0.3.1"
python = "3.12"            # must equal the environment's Python
resource_class = "cpu"     # cpu | memory | disk | gpu

[entry]
script = "src/main.py"
args = ["--epochs", "10"]

[environment]              # written by `udcs env use`
digest = "<64 hex characters>"
requirements = ["numpy==2.1.3", "scipy==1.14.1"]

[[datasets]]               # written by `udcs dataset add`
name = "train"             # read-only at inputs/train/
digest = "<64 hex characters>"

[files]
include = ["src/**/*.py", "configs/*.yaml"]   # what is packaged (an allowlist)
allow_flagged = []

[limits]                   # can only lower the deployment's limits
max_runtime_seconds = 3600
max_output_bytes = 268435456
max_output_files = 1000

[config]                   # given to your code as config.json
seed = 42
```

**What your code sees when it runs:**
- the working directory holds `src/`, `inputs/<name>/`, `config.json` and `out/`;
- **write results only under `out/`**;
- there is **no network access**.

## 3. Dependencies: approved environments only

Nothing is ever installed on lab PCs. No pip, no `setup.py`, no internet. Instead, administrators build and approve **environments**: prebuilt, wheel-only Python installations with a fixed lock of package versions.

```
udcs env list                  # approved environments
udcs env show sci-py312        # its Python version, platform and every package it provides
udcs env use sci-py312         # writes the digest and Python version into udcs.toml
```

Then declare what you import as exact pins (`"numpy==2.1.3"`); ranges are refused. `udcs check` tells you if a pin is missing and which version the environment provides instead.

**Need a package that no environment has?** Ask your administrator. A new environment is a reviewed change, not something the client can do.

## 4. Data

**Attaching an existing dataset.** Datasets are uploaded separately from code, and an administrator approves them before any package can use them:

```
udcs dataset list
udcs dataset add train measurements==2026-10      # mount name, then the dataset
```

**Uploading your own data:**

```
udcs dataset push ./measurements --name measurements --version 2026-10
```

It prints a digest. Give that to your administrator for approval. Until it is approved, `udcs dataset add` cannot find it.

## 5. Check before uploading

```
udcs check            # or: udcs check --offline (no server checks)
```

**What `check` verifies:**
- the spec;
- which files are packaged, and which were excluded and why;
- safe file names (no reserved names, links, junctions or case collisions);
- the deployment's size limits;
- the environment (approved, the same Python, every pin present);
- the datasets (approved);
- whether running user code is enabled.

It never uploads anything.

**Never packaged, whatever `include` says:**
- version control (`.git` and similar);
- caches (`__pycache__`, `.pytest_cache`, …) and virtual environments;
- old results (`udcs-results/`);
- well-known secret files: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `credentials*.json`, `.ssh/`, `.aws/` and similar.

Naming one of these explicitly is an error, not a silent drop.

**Secret heuristic.** `check` also looks for likely secrets inside selected files: private keys, cloud and GitHub tokens, `password = "..."`.
- This is a **heuristic, not a guarantee**; the `include` allowlist is the real control.
- For a false positive, list the exact path under `files.allow_flagged`.

## 6. Submit and monitor

```
udcs submit                    # check, upload, register, then submit
udcs jobs                      # your jobs
udcs status JOB
udcs watch JOB                 # follow progress and logs; Ctrl-C detaches, it does not cancel
udcs logs JOB [--follow]
udcs cancel JOB
```

**Uploads:**
- They are chunked and resumable.
- Files you already uploaded are not sent again.
- Many small files are slow, about 13 per second, so put large or numerous data files in a dataset.

**While user code is disabled:** `submit` uploads and registers the package and then stops, with exit code 3. When your administrator enables it, run `udcs submit` again; nothing is re-uploaded.

**Trying the pipeline today:** catalog jobs work now:

```
udcs submit --catalog cpu --units 100000
```

## 7. Fetch verified results

```
udcs fetch JOB                 # into udcs-results/<job>/
udcs fetch JOB -o results/ --resume
```

**Every output file is checked before it is kept:**
- it is downloaded to a temporary file;
- its SHA-256 is checked;
- it is placed **without ever overwriting** an existing file.

**Refused outright:** paths that would escape the target directory, junctions planted in it, and outputs from a different attempt than the job's.

**`udcs-receipt.json`** records the job, the attempt, the package and every file's hash.

**What "verified" means.** The files are exactly what the lab PC reported. This proves the download is intact. It does **not** prove that the lab PC computed them correctly (threat T26).

For catalog jobs, `fetch` recomputes the expected checksum locally rather than trusting the server's verdict.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Usage: nothing to do, not confirmed, not found |
| 2 | The project or spec is invalid |
| 3 | Running user code is disabled on this deployment |
| 4 | Server, network or authentication problem |
| 5 | A hash, size or path check failed |
| 6 | `watch`: the job ended failed or cancelled |
