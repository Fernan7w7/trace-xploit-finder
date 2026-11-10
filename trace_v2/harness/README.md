# Foundry harness

The bridge runs every candidate exploit inside a throwaway Foundry project that
**symlinks this directory's `lib/`**. You therefore need `forge-std` installed here
once (it is intentionally not committed — it is a git dependency):

```bash
cd trace_v2/harness
forge install foundry-rs/forge-std@v1.16.2
```

That creates `trace_v2/harness/lib/forge-std`. `out/`, `cache/`, and `lib/` are all
git-ignored and regenerated locally. `foundry.toml` is the only committed file here.
