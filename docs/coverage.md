# Coverage workflow

The project pins both the coverage runner (`cargo-llvm-cov`) and Rust's `llvm-tools-preview` component in the root `mise.toml`, so local development and GitHub Actions share exactly the same coverage commands.

```sh
mise install
mise run coverage
mise run coverage:lcov
```

The second command writes `lcov.info` for the Codecov upload in `.github/workflows/coverage.yml`. Codecov authentication remains in the GitHub Actions `CODECOV_TOKEN` secret; mise itself does not publish coverage reports.

`cargo-llvm-cov` is installed using mise's `cargo:` backend. Depending on the host, it may compile from source, which makes cold installs slower than a direct prebuilt-binary download. Once installed, it is reused across subsequent runs.
