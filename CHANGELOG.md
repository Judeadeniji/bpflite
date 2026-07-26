# Changelog

## [0.5.0-beta.0](https://github.com/Judeadeniji/bpflite/compare/v0.4.0-beta.0...v0.5.0-beta.0) (2026-07-26)


### Features

* Add 5 new tracers (unlink, mount, setuid, bpf, module) ([#20](https://github.com/Judeadeniji/bpflite/issues/20)) ([d1042fb](https://github.com/Judeadeniji/bpflite/commit/d1042fb5b9914fcd4360400a09c0baebc6ef47d9))
* Add Command Palette (Ctrl+P) for TUI tracer navigation ([050af5d](https://github.com/Judeadeniji/bpflite/commit/050af5d50fe42f93ada481db7848b9d7f59a88f4))
* allow turning off filters using the Esc key ([7a500be](https://github.com/Judeadeniji/bpflite/commit/7a500be50a01de2b2ea8921b36c3339b447444b6))
* implement eBPF out-of-memory (OOM) kills tracer ([#16](https://github.com/Judeadeniji/bpflite/issues/16)) ([43e781d](https://github.com/Judeadeniji/bpflite/commit/43e781d8d0b65e05b7cd7974f8fc92be9dd58d9a))
* redesign header UI to include logo and shortcuts ([64806b3](https://github.com/Judeadeniji/bpflite/commit/64806b3e30b1907449c855df4e66081fed4aef40))
* solid full-width header and fix 's' shortcut ([a1191ec](https://github.com/Judeadeniji/bpflite/commit/a1191ec1e0f5e100b2ddfc7c91b57d2f86db03f5))
* use lipgloss v2 Canvas for modal overlay ([180ec3c](https://github.com/Judeadeniji/bpflite/commit/180ec3c02c5565118d151f7570a30aa5d421fda4))
* use lumberjack for log rotation and slog for structured logging ([#19](https://github.com/Judeadeniji/bpflite/issues/19)) ([c533232](https://github.com/Judeadeniji/bpflite/commit/c533232edf5be6a6c600b1e7bc4b946614e91a17))


### Bug Fixes

* account for outer box border in header width to prevent wrapping ([c7313ff](https://github.com/Judeadeniji/bpflite/commit/c7313ffbc884d3ca352e36080dba08c3f0046ed3))
* correctly compose modal using lipgloss NewCompositor ([c1cc605](https://github.com/Judeadeniji/bpflite/commit/c1cc6057e16f290f16dea876c6ca5bd985c61835))
* enable true fuzzy finding inside the modal by setting filter state on open and not intercepting keystrokes ([493c1bf](https://github.com/Judeadeniji/bpflite/commit/493c1bf326bdeb6bee4bfa399bd9db2326245413))
* handle negative terminal width panic during initialization ([8ef322f](https://github.com/Judeadeniji/bpflite/commit/8ef322fb99c6c56531a1d5b035f382381cfce6eb))
* Re-enable alt screen via View.AltScreen=true (bubbletea v2 API) ([2c6e8d1](https://github.com/Judeadeniji/bpflite/commit/2c6e8d14527b3a315f132664eef3a3c7fd60ba8c))
* remove hardcoded modal height so it tightly wraps the list ([30c9da6](https://github.com/Judeadeniji/bpflite/commit/30c9da64189ffc390a6918bb8700fb5bfec5aaa4))
* Render Command Palette as a centered modal instead of full screen (and fix Makefile buildvcs) ([29f6fc6](https://github.com/Judeadeniji/bpflite/commit/29f6fc6fc0deb493b6472348d04fbc4d62392140))
* Render palette as true composited modal over live event table ([821dd2f](https://github.com/Judeadeniji/bpflite/commit/821dd2fe09c6d8317790923e0b013a1abd7c1d4a))
* resolve modal empty items and text input black background spots ([261a05e](https://github.com/Judeadeniji/bpflite/commit/261a05e2b42395db9369a5368541c647d2b25be8))
* stabilize modal width and fix black halfblocks on border ([a3abe8f](https://github.com/Judeadeniji/bpflite/commit/a3abe8fa33001986f4baf51a21d853a65eb6f9b4))
* Throttle TUI table updates to prevent visual tearing ([#22](https://github.com/Judeadeniji/bpflite/issues/22)) ([ab8f62c](https://github.com/Judeadeniji/bpflite/commit/ab8f62c2c64c23a78d727339765559ca57cd8616))
* update font size and remove sudo from bpflite command in demo tape ([30b4bec](https://github.com/Judeadeniji/bpflite/commit/30b4bec401d0470e7e275f4c3882e34682cd57fc))

## [0.4.0-beta.0](https://github.com/Judeadeniji/bpflite/compare/v0.3.0-beta.0...v0.4.0-beta.0) (2026-07-25)


### Features

* add trace all command and tui tabs for easy switching ([#13](https://github.com/Judeadeniji/bpflite/issues/13)) ([777e496](https://github.com/Judeadeniji/bpflite/commit/777e4963eef35849ffcd4eefaabcee2664e93866))
* implement eBPF signals tracer (kill syscalls) ([#15](https://github.com/Judeadeniji/bpflite/issues/15)) ([f83399d](https://github.com/Judeadeniji/bpflite/commit/f83399d0b04676a6abe6364e924903251559d271))

## [0.3.0-beta.0](https://github.com/Judeadeniji/bpflite/compare/v0.2.0-beta.0...v0.3.0-beta.0) (2026-07-25)


### Features

* add --json output for history and new dump command ([49724a9](https://github.com/Judeadeniji/bpflite/commit/49724a9fb6922e08e9a27d5bb8256afe1ebc4cf2))
* add format flag and lipgloss styling to history command ([21ffb10](https://github.com/Judeadeniji/bpflite/commit/21ffb107283cfb641564a82b69d63d8177801c76))
* implement Cobra CLI, BubbleTea TUI, and daemon commands ([956e8a0](https://github.com/Judeadeniji/bpflite/commit/956e8a0cc81b89d79d4a60f4a07c32322aefcda1))
* **v0.2:** implement network tracing via inet_sock_set_state ([d3abe89](https://github.com/Judeadeniji/bpflite/commit/d3abe89432c27468c601ac963b39a72bea9c6fe9))
* **v0.3:** implement SQLite historical logging ([26341d1](https://github.com/Judeadeniji/bpflite/commit/26341d18d3aa2dd0afde8e6af1a111282293b839))


### Bug Fixes

* correct .gitignore and remove old test file ([e836455](https://github.com/Judeadeniji/bpflite/commit/e83645518148e41fa2af74cda8fffcaeab7b605f))
* vendor libbpf headers to ensure fully hermetic CI builds ([#10](https://github.com/Judeadeniji/bpflite/issues/10)) ([d6aeeac](https://github.com/Judeadeniji/bpflite/commit/d6aeeac9ac1b0c4b376573fe53973603906b8a10))
* vendor vmlinux.h for CI builds ([#6](https://github.com/Judeadeniji/bpflite/issues/6)) ([0d77661](https://github.com/Judeadeniji/bpflite/commit/0d7766190fe557c9bc76886583ad4dc22389c2dc))

## [0.2.0-beta.0](https://github.com/Judeadeniji/bpflite/compare/v0.1.0-beta.0...v0.2.0-beta.0) (2026-07-25)


### Features

* add --json output for history and new dump command ([49724a9](https://github.com/Judeadeniji/bpflite/commit/49724a9fb6922e08e9a27d5bb8256afe1ebc4cf2))
* add format flag and lipgloss styling to history command ([21ffb10](https://github.com/Judeadeniji/bpflite/commit/21ffb107283cfb641564a82b69d63d8177801c76))
* implement Cobra CLI, BubbleTea TUI, and daemon commands ([956e8a0](https://github.com/Judeadeniji/bpflite/commit/956e8a0cc81b89d79d4a60f4a07c32322aefcda1))
* **v0.2:** implement network tracing via inet_sock_set_state ([d3abe89](https://github.com/Judeadeniji/bpflite/commit/d3abe89432c27468c601ac963b39a72bea9c6fe9))
* **v0.3:** implement SQLite historical logging ([26341d1](https://github.com/Judeadeniji/bpflite/commit/26341d18d3aa2dd0afde8e6af1a111282293b839))


### Bug Fixes

* correct .gitignore and remove old test file ([e836455](https://github.com/Judeadeniji/bpflite/commit/e83645518148e41fa2af74cda8fffcaeab7b605f))
* vendor vmlinux.h for CI builds ([#6](https://github.com/Judeadeniji/bpflite/issues/6)) ([0d77661](https://github.com/Judeadeniji/bpflite/commit/0d7766190fe557c9bc76886583ad4dc22389c2dc))
