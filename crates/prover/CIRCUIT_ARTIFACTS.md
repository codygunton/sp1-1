# Building and Releasing Circuit Artifacts

This doc describes how to build and release circuit artifacts for the SP1 prover.

## Build the artifacts

From this directory, run:

```bash
make build-artifacts
```

This puts circuit artifacts in `build/<circuit_type>/`. 

## Optional: Groth16 Trusted Setup

By default, the groth16 pk / vk are generated using local randomness, leaving the possibility of a trapdoor. For production releases, we use a trusted setup ceremony to generate the pk / vk. For more information, see this doc [MODERATOR.md](https://github.com/succinctlabs/semaphore-gnark-11/blob/e6e347178b693c217aa844b18779c85351c23fbc/MODERATOR.md).

Following the instructions there will generate a `groth16_pk.bin` and `groth16_vk.bin`, which gets copied to the `build/groth16/` directory.



## Release circuits

From this directory, run:

```bash
make release-circuits
```

If you did a trusted setup, run

```bash
make release-circuits-with-trusted-setup
```

This will upload the circuits and optionally the trusted setup transcript to this SP1 version's S3 bucket.
