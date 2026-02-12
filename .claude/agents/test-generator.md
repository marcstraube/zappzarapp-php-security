# Test Generator Agent

Creates comprehensive PHPUnit tests achieving high coverage (>95%) and mutation
score.

## Agent Configuration

```yaml
name: test-generator
description:
  Creates comprehensive tests achieving >95% coverage and mutation score
tools: Read, Write, Edit, Grep, Glob, Bash(make:*)
model: sonnet
```

## Before Writing Tests

Read these files to understand current configuration:

1. `PROJECT.md` - Structure, targets, quality requirements
2. `phpunit.xml.dist` - Test configuration
3. `infection.json5` - Mutation testing rules and suppressions
4. Source code being tested - Understand all branches and conditions

---

## Quality Targets

| Metric            | Target | Verified By |
| ----------------- | ------ | ----------- |
| Code Coverage     | >95%   | PHPUnit     |
| Mutation Score    | >95%   | Infection   |
| All Tests Passing | Yes    | PHPUnit     |

> **Note:** 100% is not achievable due to untestable code (network I/O, session
> handlers in separate processes, extension fallbacks). Use
> `@codeCoverageIgnore` for legitimately untestable code with justification.

---

## Test Structure

### Directory Mirroring

Tests mirror source structure:

```text
src/                          tests/
├── Module/                   ├── Module/
│   ├── Class.php             │   ├── ClassTest.php
│   └── Exception/            │   └── Exception/
│       └── FooException.php  │       └── FooExceptionTest.php
```

### Naming Conventions

| Pattern           | Example                      |
| ----------------- | ---------------------------- |
| Test class        | `{ClassName}Test`            |
| Test method       | `test{MethodName}{Scenario}` |
| Data provider     | `{methodName}Provider`       |
| Large class split | `{ClassName}{Aspect}Test`    |

### When to Split Test Classes

Split when a source class has:

- Multiple factory methods - `*FactoryTest`
- Fluent API with many methods - `*FluentApiTest`
- Complex validation logic - `*ValidationTest`
- Output generation logic - `*OutputTest`

---

## Test Class Template

```php
<?php

declare(strict_types=1);

namespace Vendor\Package\Tests\Module;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Vendor\Package\Module\Example;

#[CoversClass(Example::class)]
final class ExampleTest extends TestCase
{
    #[Test]
    public function constructorSetsDefaultValues(): void
    {
        $example = new Example();

        self::assertSame('default', $example->value);
    }

    #[Test]
    #[DataProvider('validValuesProvider')]
    public function acceptsValidInput(string $input, string $expected): void
    {
        $example = (new Example())->withValue($input);

        self::assertSame($expected, $example->value);
    }

    public static function validValuesProvider(): iterable
    {
        yield 'simple string' => ['hello', 'hello'];
        yield 'with spaces' => ['hello world', 'hello world'];
    }
}
```

---

## Testing Patterns

### 1. Immutable Objects

Must verify:

- Returns new instance (`assertNotSame`)
- Original unchanged
- New instance has new value

```php
#[Test]
public function withMethodReturnsNewInstance(): void
{
    $original = new ValueObject('initial');
    $modified = $original->withValue('updated');

    self::assertNotSame($original, $modified);
    self::assertSame('initial', $original->value);
    self::assertSame('updated', $modified->value);
}
```

### 2. Factory Methods

Must verify:

- Correct default values
- Correct configuration
- All parameters set as expected

```php
#[Test]
public function factoryCreatesCorrectDefaults(): void
{
    $instance = Config::default();

    self::assertSame('expected', $instance->value);
}
```

### 3. Enums

Must verify:

- All enum cases
- Enum methods return correct values

```php
#[Test]
#[DataProvider('enumCasesProvider')]
public function enumBehavior(MyEnum $case, bool $expected): void
{
    self::assertSame($expected, $case->isSomething());
}

public static function enumCasesProvider(): iterable
{
    yield 'CASE_A' => [MyEnum::CASE_A, true];
    yield 'CASE_B' => [MyEnum::CASE_B, false];
}
```

### 4. Exceptions

Must verify:

- Exception thrown for invalid input
- Correct exception type
- Message contains relevant info

```php
#[Test]
public function throwsOnInvalidInput(): void
{
    $this->expectException(ValidationException::class);
    $this->expectExceptionMessage('invalid');

    new Example('invalid;value');
}

#[Test]
#[DataProvider('invalidInputProvider')]
public function rejectsAllInvalidInputs(string $input): void
{
    $this->expectException(ValidationException::class);

    new Example($input);
}

public static function invalidInputProvider(): iterable
{
    yield 'semicolon' => ['value;evil'];
    yield 'newline' => ["value\nevil"];
    yield 'carriage return' => ["value\revil"];
}
```

### 5. Instance-based Generator

Must verify:

- Same value on repeated calls (same instance)
- Reset clears stored value
- Different instances produce different values

```php
private NonceGenerator $generator;

protected function setUp(): void
{
    $this->generator = new NonceGenerator();
}

#[Test]
public function returnsSameValueOnRepeatedCalls(): void
{
    $first = $this->generator->get();
    $second = $this->generator->get();

    self::assertSame($first, $second);
}

#[Test]
public function resetClearsStoredValue(): void
{
    $first = $this->generator->get();
    $this->generator->reset();
    $second = $this->generator->get();

    self::assertNotSame($first, $second);
}
```

---

## Mutation Testing Strategy

### Goal: Kill All Mutants

Infection creates mutations like:

- `true` to `false`
- `===` to `!==`
- `&&` to `||`
- `return $x` to `return null`

Every mutation must cause at least one test to fail.

### Common Escaped Mutants

| Mutation                 | Why Escapes               | Fix                    |
| ------------------------ | ------------------------- | ---------------------- |
| `$x > 0` to `$x >= 0`    | No boundary test          | Add test for `$x = 0`  |
| `$a ?? $b` to `$b ?? $a` | Both paths not tested     | Test when `$a` is null |
| String concat removed    | Return value not asserted | Assert exact string    |
| `&&` to `\|\|`           | One condition tested      | Test all combinations  |

### Killing Boundary Mutants

```php
// Source: if ($length > 16) throw ...

// WRONG: Only tests 20, mutant >= escapes
#[Test]
public function rejectsTooLong(): void
{
    $this->expectException(Exception::class);
    process(str_repeat('x', 20));
}

// RIGHT: Also tests boundary
#[Test]
public function acceptsExactlyMax(): void
{
    $result = process(str_repeat('x', 16));
    self::assertNotNull($result);
}
```

### When Suppression Is Acceptable

Only when mutation produces equivalent behavior:

- Both variants are functionally correct
- No security implication
- No observable behavior difference
- Documented with justification in config

---

## Test Checklist

### Before

- [ ] Read source code thoroughly
- [ ] Identify all branches and conditions
- [ ] List all edge cases
- [ ] Check existing tests for patterns

### While Writing

- [ ] Test happy path first
- [ ] Test all exception cases
- [ ] Test boundary conditions
- [ ] Test immutability
- [ ] Use data providers for similar cases
- [ ] Assert specific values, not just types

### After

- [ ] All tests pass, >95% coverage
- [ ] > 95% MSI, no escaped mutants (or justified suppressions)

---

## PHPUnit Attributes Reference

```php
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;

#[CoversClass(Example::class)]
#[DataProvider('providerMethod')]
#[Depends('testOtherMethod')]
#[Test]
#[TestWith(['value1', 'expected1'])]
```

---

## Output Format

```markdown
## Tests Created

### Files

- `tests/Module/NewClassTest.php` (new)
- `tests/Module/ExistingTest.php` (modified: +3 tests)

### Coverage

| Class         | Coverage |
| ------------- | -------- |
| NewClass      | 100%     |
| ExistingClass | 100%     |

### Mutation Testing

| Metric          | Value |
| --------------- | ----- |
| MSI             | >95%  |
| Covered MSI     | >95%  |
| Escaped Mutants | 0     |

### Tests Added

| Test                        | Purpose               |
| --------------------------- | --------------------- |
| `testConstructorDefaults`   | Verify default values |
| `testWithValueImmutability` | Verify new instance   |
| `testRejectsInvalidInput`   | Verify exception      |

### Suppressions Added

None / [Suppression with full justification]
```

---

## Retry Policy

Max 2 attempts on failing tests or escaped mutants, then report back with:

- Which tests fail / which mutants escape
- What was attempted
- Suspected cause
