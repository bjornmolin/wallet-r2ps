# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-04-28

### Changed

- Wip

## [0.1.1] - 2026-04-28

### Changed

- Wip

## [0.0.5] - 2026-04-28

### Changed

- Wip

## [0.0.4] - 2026-04-28

### Changed

- Merge pull request #2 from bjornmolin/feat/test-rust-release
- Wip

## [0.0.2] - 2026-04-28

### Changed

- Wip
- Merge pull request #1 from bjornmolin/feat/try-ci-bm

## [0.0.1] - 2026-04-28

### Added

- Add replay protection
- Add file to safe.directory
- Address PR feedback
- Add hsm-verify container, fix license/gitignore, bump cargo-audit
- Add hsm-common shared crate (protocol + jose), rename WorkerResponse
- Add github actions and just linting rust projects
- Add licence headers and files
- Add the ability to derive OPAQUE and JWS keys from a HSM protected root key
- Add digg-hsm-keytool CLI binary
- Add integration load tests for bff and worker
- Add unit-tests
- Add and refactor worker_service tests
- Add unit-tests
- Add unit-tests for state
- Add tests for in-memory session state.
- Add error reporting on kafka
- Add curl-static to rdkafka
- Add distinct type for HsmWrappedKey
- Add configuration for serialized opaque server setup
- Add TODO for making service_request.context obsolete
- Add helper to debug-log JSON or hex data
- Add info logging for server start and significant request/response events
- Add define_byte_vector! for distinct types of Vec<u8>
- Add state in valkey support in rest api
- Add delete hsm delete key

### Changed

- Bump reusable-ci pin to 6c98d46f for cargo-audit CVSS 4.0 fix
- Try reusable-ci v2.8.0 first-class Rust support [SMOKE TEST]
- Merge pull request #94 from diggsweden/renovate/actions-cache-5.x
- Update actions/cache action to v5
- Merge pull request #95 from diggsweden/renovate/actions-checkout-6.x
- Update actions/checkout action to v6
- Update rust docker tag to v1.94 (#92)
- Merge pull request #86 from diggsweden/renovate/github-actions
- Update github actions
- Merge pull request #91 from diggsweden/pipeline
- TestContainer in pipeline
- Adjust for workspace
- Bump commit linter
- Merge pull request #89 from diggsweden/fixMdLintError
- Merge pull request #83 from diggsweden/replay
- Move nonce to outerRequest
- Merge pull request #80 from diggsweden/ft-refactor_common
- Merge pull request #82 from diggsweden/dockerFileFix
- Integrate hsm-common types and clean up domain
- Merge pull request #81 from diggsweden/chore/bump-reusable-ci-v2.7.9
- Switch rumdl from ubi to aqua, bump gommitlint to 0.9.10
- Bump reusable-ci to v2.7.9
- Merge pull request #73 from diggsweden/feat/just-lint
- Merge pull request #71 from diggsweden/tests
- Update makefiles and add unit tests
- Merge pull request #72 from diggsweden/feat/reuse
- Merge pull request #70 from diggsweden/ft-rename_r2ps_worker
- Rename rust-r2ps-worker to hsm-worker
- Merge pull request #69 from diggsweden/testContainer
- Test-container tests
- Merge pull request #67 from diggsweden/semiIntegrationTests
- Self contained integration tests
- Merge pull request #66 from diggsweden/ft-first_key_derivation
- Merge pull request #65 from diggsweden/refactorTests
- Move and refactor tests
- Introduce mockall
- Merge pull request #59 from diggsweden/feat/max-one-hsm-sign-per-auth-session
- Block multiple hsm operations in a session
- Merge pull request #64 from diggsweden/feat/e2e-load-tests
- Merge pull request #63 from diggsweden/moreUnitTests
- Merge pull request #62 from diggsweden/workerServiceTests
- Merge pull request #61 from diggsweden/unitTest
- Merge pull request #60 from diggsweden/rustRest
- Introduce wallet-bff
- Merge pull request #56 from diggsweden/stateTests
- Merge pull request #58 from diggsweden/ft-missing_tests
- Update reusable-ci to v2.7.3
- Merge pull request #53 from diggsweden/tests
- Unit tests
- Merge pull request #54 from diggsweden/ft-in_memory_cache
- Unify session state into single FSM cache
- Merge pull request #52 from diggsweden/removeCrates
- Merge pull request #51 from diggsweden/changePin
- ChangePin
- Merge pull request #47 from diggsweden/errorHandling
- Merge pull request #49 from diggsweden/ft-errorHandling2
- Restructure error handling with typed visibility enum
- Merge pull request #48 from diggsweden/ft-jose_port_adapter
- Refactor use of josekit behind a port/adapter
- Merge pull request #46 from diggsweden/ft-opaque_port_adapter
- Reformat with cargo fmt
- Refactor use of opaque_ke behind a port/adapter
- Merge pull request #45 from diggsweden/decryptionEnum
- Refactor decryption
- Merge pull request #44 from diggsweden/betterState
- Only send changed state
- Merge pull request #43 from diggsweden/feat/generate-docs-pr
- Typed jws and jwe and generate docs from code
- Merge pull request #42 from diggsweden/ft-dynamic_registration
- Facilitate dynamic registration of clients
- Merge pull request #40 from diggsweden/execute
- Create bootstrap
- Refactor worker_service
- Break up worker_service execute
- Merge pull request #39 from diggsweden/ft-initial_state_from_worker
- Move state JWS encode/decode to DeviceHsmState
- Have Java REST API request new state from Rust hsm-worker
- Merge pull request #38 from diggsweden/clippy
- Merge pull request #37 from diggsweden/fixEnv
- Merge pull request #36 from diggsweden/ft-improved_state
- Make OPAQUE context configurable, and fix things in .env*
- Re-organise DeviceHsmState
- Merge pull request #35 from diggsweden/feat/feat/config-ddd-port-adapter-arch
- Refactor config of app in DDD port-adapter architecture
- Merge pull request #34 from diggsweden/ft-jose_soup
- Sign initial state with hsm-workers development key instead of a random one
- Extract actual public key from X.509 certificate
- Update JWS signing/verifying to use josekit
- Use josekit for JWE encryption without PEM
- Clean up requests
- Merge pull request #32 from diggsweden/ft-rework_protocol
- Re-work protocol with cleaner layering, better names, better data types.
- Merge pull request #29 from diggsweden/fix/volume-permission-linux-and-docs
- Merge pull request #28 from diggsweden/ft-inner_outer
- Further remain intermediate R2psRequest to clarify purpose
- Rename ServiceRequest to OuterRequest and various different names to Inner(something)
- Merge pull request #27 from diggsweden/feat/survive-restart-and-rebuild
- Merge pull request #26 from diggsweden/ft-refactor_opaque_requests
- Refactor authenticate and register from 2+2 operations to 4
- Merge pull request #25 from diggsweden/ft-logging
- Change all existing logging to use debug instead of info
- Merge pull request #24 from diggsweden/lessB64
- Merge pull request #23 from diggsweden/time
- Expiry times is ISO duration
- Merge pull request #20 from diggsweden/ft-refactor_operations
- Merge branch 'main' into ft-refactor_operations
- Clean up struct R2psService and it's init
- Refactor operations out of r2ps_service.rs into a submodule
- Merge pull request #18 from diggsweden/feat/remove-java-worker-improve-docs
- Merge pull request #21 from diggsweden/feat/use-4-0-1-opaque-ke
- Use official version of opaque-ke instead of github version
- Merge pull request #19 from diggsweden/hsmKeyJwk
- Return public hsm key as JWK
- Merge pull request #17 from diggsweden/feat/state-in-req-resp
- Correct config for kafka-3 in docker
- Correct config for rust worker in docker
- Merge pull request #16 from diggsweden/ft-byte_vectors
- Only fetch session key once for decrypt and then encrypt
- Use distinct byte vector type for DecryptedData
- Use distinct byte vector type for SessionKey
- Format with rustfmt
- Merge pull request #15 from diggsweden/ft-restore_execute_logic
- Move decryption of service_data back up one level in the call-stack
- Move state to topic work in progress
- Merge pull request #12 from diggsweden/lint
- Linting with clippy
- Merge pull request #11 from diggsweden/deleteKey
- Merge pull request #9 from diggsweden/ft-enc_handling
- Merge branch 'main' into ft-enc_handling
- R2ps_service (#8)
- Ignore some unused results
- Set "enc" correctly in service responses
- Minor additions
- Merge pull request #6 from diggsweden/refactorRust
- Setup
- Merge pull request #5 from diggsweden/first
- Initial commit
- Initial commit

### Fixed

- Markdown linter error
- Review fixes of adr
- Update container builds for workspace structure with hsm-common
- Correct worker_flow_test
- Refactor bootstrap, add keytool to container
- Restore removed types
- Default to one sign per session
- Move creating clients out of main loop
- Clippy warnings
- Throwing exceptions cause Kafka to retry - return silently instead
- Rename
- Refactor r2ps_service construction
- Correct serverid in docker conf
- Keep jws signer and verifier in memory and clean up config
- Correct config for local dev with softhsm tokens
- Correct server public key config
- Fix padding (and improve debug) and linux server_public_key
- Fix test case with valid data
- Avoid converting JWK to PEM when verifying JWS
- Naming
- Volume file permission on linux and add docs
- Pretty-print ServiceRequest to avoid wall-of-text
- Better naming
- Correct signing (#10)
- Correct failing tests after merges
- Start rust worker after init kafka completed

### Removed

- Remove request_counter
- Remove false Option
- Remove unused crates
- Remove debug info log
- Remove unused import
- Remove now unused jsonwebtoken
- Remove unneeded variables
- Remove unused code/variables
- Remove redundantly stored curve (also in public_key_jwk)
- Remove unused variable for pkcs11 tools
- Remove spurious printlns
- Remove double b64
- Remove old code and improve readme
- Remove never-changed data from R2psResponse

[0.1.2]: https://github.com/bjornmolin/wallet-r2ps/compare/v0.1.1..v0.1.2
[0.1.1]: https://github.com/bjornmolin/wallet-r2ps/compare/v0.0.5..v0.1.1
[0.0.5]: https://github.com/bjornmolin/wallet-r2ps/compare/v0.0.4..v0.0.5
[0.0.4]: https://github.com/bjornmolin/wallet-r2ps/compare/v0.0.2..v0.0.4
[0.0.2]: https://github.com/bjornmolin/wallet-r2ps/compare/v0.0.1..v0.0.2

<!-- generated by git-cliff -->
