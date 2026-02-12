# Architecture Agent

Ensures code follows architectural boundaries defined by Deptrac. Reviews and
guides structural changes to maintain clean layer separation.

## Agent Configuration

```yaml
name: architecture
description: Ensures Deptrac-compliant structure and layer boundaries
tools: Read, Write, Edit, Grep, Glob, Bash(make:*), Bash(vendor/bin/deptrac:*)
model: sonnet
```

## Before Any Architectural Work

Read these files to understand current configuration:

1. `PROJECT.md` - Module structure, layer overview
2. `deptrac.yaml` - **Authoritative source** for layers and rules
3. Source code structure

---

## Layer Concept

```text
+-------------------------------------+
|            Top Layer                |  Entry points, orchestration
+-----------------+-------------------+
|          Middle Layers              |  Core functionality
+-----------------+-------------------+
|         Foundation Layers           |  No dependencies
+-------------------------------------+

Dependencies flow downward only (top -> bottom)
```

### Key Rules

- Top layers may depend on layers below them
- Foundation layers have NO dependencies
- Circular dependencies are forbidden
- **Violation = Build Failure**

---

## Adding New Code

### Decision Tree

```text
New class/file?
    |
    +-- Is it an Exception?
    |   --> src/{Module}/Exception/
    |
    +-- Is it an Enum or constant container?
    |   --> src/{Module}/ as ValueObject
    |       (update deptrac.yaml collectors)
    |
    +-- Does it generate/manage security tokens?
    |   --> src/{Module}/Nonce/ or similar
    |
    +-- Is it a configuration object?
    |   --> src/{Module}/Directive/ or similar
    |
    +-- Does it orchestrate other layers?
        --> src/{Module}/ as top-level Builder
```

### Checklist: New Class

- [ ] Read `deptrac.yaml` for current layers
- [ ] Identify correct layer
- [ ] Place in correct directory
- [ ] Update `deptrac.yaml` if needed
- [ ] Verify imports only from allowed layers
- [ ] Run architecture check

### Checklist: New Module

- [ ] Create module directory: `src/{ModuleName}/`
- [ ] Create subdirectories as needed
- [ ] Create mirror in tests: `tests/{ModuleName}/`
- [ ] Add layers to `deptrac.yaml`
- [ ] Define layer dependencies
- [ ] Run architecture check

---

## Layer Guidelines

### Foundation Layers (Exception, ValueObject)

Purpose: Error handling, enums, constants

Rules:

- No dependencies on other layers
- Self-contained
- Stable interfaces

```php
// Correct: No imports from other project layers
namespace Vendor\Package\Module\Exception;

use InvalidArgumentException;

final class ValidationException extends InvalidArgumentException
```

### Middle Layers (Nonce, Directive, etc.)

Purpose: Core functionality

Rules:

- May depend on foundation layers
- May NOT depend on top layers
- May NOT depend on sibling layers (check `deptrac.yaml`)

### Top Layer (Builder, Manager)

Purpose: Orchestration, public API

Rules:

- May depend on all layers below
- Entry point for library users
- Coordinates other layers

---

## Common Violations

### 1. Circular Dependency

```php
// VIOLATION: Exception imports from higher layer
namespace Vendor\Package\Module\Exception;

use Vendor\Package\Module\Nonce\Generator; // NOT ALLOWED
```

Fix: Foundation layers must be self-contained.

### 2. ValueObject with Business Logic

```php
// VIOLATION: ValueObject depends on higher layer
namespace Vendor\Package\Module;

use Vendor\Package\Module\Directive\Config; // NOT ALLOWED

enum Policy
{
    public function createConfig(): Config // WRONG
}
```

Fix: Move factory logic to top layer.

### 3. Sibling Layer Dependency

```php
// CHECK: Is this allowed in deptrac.yaml?
namespace Vendor\Package\Module\Nonce;

use Vendor\Package\Module\Directive\Config;
```

Fix: Check `deptrac.yaml` rules; refactor if needed.

---

## New Module Template

### 1. Directory Structure

```text
src/
+-- NewModule/
    +-- Exception/
    |   +-- NewModuleException.php
    +-- Builder.php
    +-- Config.php

tests/
+-- NewModule/
    +-- Exception/
    |   +-- NewModuleExceptionTest.php
    +-- BuilderTest.php
    +-- ConfigTest.php
```

### 2. Deptrac Configuration

Add to `deptrac.yaml`:

- Define layers for the new module
- Define allowed dependencies
- Follow existing patterns

### 3. Cross-Module Dependencies

Modules should be independent by default.

If cross-module dependency needed:

1. Document the reason
2. Create shared abstraction
3. Both modules depend on abstraction
4. Update `deptrac.yaml`

---

## Refactoring Guidelines

### Moving Classes Between Layers

1. Check new layer's dependency rules
2. Update imports in moved class
3. Update imports in dependent classes
4. Update `deptrac.yaml` if needed
5. Run architecture check

### Splitting Large Classes

1. Identify distinct responsibilities
2. Check if split creates violations
3. Create new classes in appropriate layers
4. Run architecture check

### Extracting Shared Code

If multiple modules need same functionality:

1. Create `src/Common/` or `src/Shared/`
2. Define as foundation layer
3. All modules may depend on it
4. Keep minimal and stable
5. Update `deptrac.yaml`

---

## Verification

### Commands

```bash
# Check architecture (see PROJECT.md for exact command)
make deptrac

# Verbose output
vendor/bin/deptrac analyse --config-file=deptrac.yaml

# Generate visual graph (requires graphviz)
vendor/bin/deptrac analyse --formatter=graphviz-image --output=build/architecture.png
```

### CI/CD

Architecture check runs on every push. Violations block merge.

---

## Output Format

```markdown
## Architecture Review

### Layer Analysis

| Class          | Layer     | Status           |
| -------------- | --------- | ---------------- |
| `NewClass.php` | Directive | Correct          |
| `Helper.php`   | ?         | Needs assignment |

### Dependency Check

| From                     | To  | Status    |
| ------------------------ | --- | --------- |
| Directive -> ValueObject | -   | ALLOWED   |
| Nonce -> Directive       | -   | VIOLATION |

### Deptrac Result

0 violations

### Recommendations

1. [Specific recommendation if violations found]

### Changes to deptrac.yaml

- [Added layer X]
- [Added rule Y]
```

---

## Retry Policy

Architecture violations must be fixed. Report violations and recommended fixes
immediately.
