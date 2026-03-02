# Status: Issue #1374

## Task

Add CodeRabbit config for AI-powered API lint review

## Progress

- [x] Understanding complete
- [x] Implementation started
- [x] Pre-commit checks passing
- [x] All changes committed

## Subtasks

1. Create `.coderabbit.yaml` with chill profile and disabled noisy features
2. Add path_instructions for C-CALLER-CONTROL on payjoin/src and payjoin-cli/src
3. Add Rust API guidelines checklist instructions
4. Run pre-commit checks
5. Commit
6. Write PULL-REQUEST.md

## Decisions

- Use "chill" profile as specified in issue to minimize noise
- Disable high_level_summary, changed_files_summary, sequence_diagrams,
  estimate_code_review_effort, suggested_labels, suggested_reviewers per issue
- Target only payjoin/src/**/\*.rs and payjoin-cli/src/**/\*.rs (the two main
  crate source dirs mentioned in issue)
- Include broader Rust API guidelines checklist patterns alongside
  C-CALLER-CONTROL as suggested in the issue

## Questions

(Log anything that needs human review)

## Commits

- `7655f8e5` Add CodeRabbit config for AI-powered API review
  - Created `.coderabbit.yaml` with chill profile, disabled noisy features,
    and path_instructions for C-CALLER-CONTROL + Rust API guidelines
