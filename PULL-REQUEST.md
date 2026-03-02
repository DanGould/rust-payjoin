## Summary

- Add `.coderabbit.yaml` to enable free, advisory AI review on PRs
- Configure "chill" profile with noisy features disabled to minimize noise
- Add path-scoped instructions for `payjoin/src/**/*.rs` and `payjoin-cli/src/**/*.rs` targeting C-CALLER-CONTROL violations (pub fn taking &T but internally cloning)
- Include broader Rust API guidelines checklist patterns (C-COMMON-TRAITS, C-CONV, C-GETTER, C-ITER, C-SERDE, C-SEND-SYNC)

Closes #1374

## Changes

- `7655f8e5` Add CodeRabbit config for AI-powered API review

## Test plan

- [ ] `.coderabbit.yaml` is valid YAML
- [ ] Config uses "chill" profile (advisory only)
- [ ] C-CALLER-CONTROL instruction targets correct paths
- [ ] Noisy features (summaries, diagrams, labels, reviewers) are disabled
- [ ] Open a test PR touching `payjoin/src/` to verify CodeRabbit posts review comments

## Open questions

- CodeRabbit's general reviewer still runs alongside path instructions; if it proves too noisy the maintainer may need to tune further or consider the claude-code-action alternative from the issue
- The C-SERDE guideline is included for `payjoin/src/` but omitted from `payjoin-cli/src/` since CLI types are less likely to need serde; maintainer can adjust

Disclosure: co-authored by Claude
