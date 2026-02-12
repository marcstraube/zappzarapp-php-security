# Claude Instructions

Project-specific instructions for Claude Code.

## Quick Reference

| Resource       | Path                                           |
| -------------- | ---------------------------------------------- |
| Project config | `.claude/PROJECT.md`                           |
| Architecture   | `deptrac.yaml`                                 |
| Quality config | `phpstan.neon`, `psalm.xml`, `infection.json5` |

## Before Any Task

1. Read `.claude/PROJECT.md` for namespace, structure, and targets
2. Read tool config files as needed

---

## Quality Gates

All must pass before merge (see `.claude/PROJECT.md` for commands):

- [ ] PHPStan (Level 8)
- [ ] Psalm (Level 1)
- [ ] PHPMD
- [ ] PHP-CS-Fixer
- [ ] PHPUnit (>95% coverage)
- [ ] Deptrac (0 violations)
- [ ] Infection (100% MSI)

---

## Core Principles

### Security First

- Cryptographic randomness only (`random_bytes()`)
- Input validation (reject `;`, `\n`, `\r`)
- No banned functions (see `phpstan.neon`)
- Secure defaults, explicit opt-in for permissive

### Code Quality

- Immutable value objects (`readonly`, `with*()` returns new instance)
- Type safety (`strict_types`, enums, `@throws`)
- Architecture boundaries (Deptrac)
- High test coverage (>95%) + 100% mutation score

### No Suppressions

Suppressions are the last resort. If unavoidable:

- Document why no alternative exists
- Verify no security implication
- Add justification in code/config

---

## Commit Conventions

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

All commits must be GPG-signed.

---

## Language

- **English always**: Code, documentation, commits, technical content
- **User's language**: Direct questions and confirmations only
