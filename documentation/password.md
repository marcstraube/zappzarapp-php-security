# Password Security

Comprehensive password handling including secure hashing, validation, policy
enforcement, and pwned password detection.

## Quick Start

```php
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;

$hasher = DefaultPasswordHasher::argon2id();
$hash = $hasher->hash('MySecurePassword');
$valid = $hasher->verify('MySecurePassword', $hash);
```

## Classes

| Class                      | Description                                  |
| -------------------------- | -------------------------------------------- |
| `DefaultPasswordHasher`    | Password hashing with Argon2id or bcrypt     |
| `PepperedPasswordHasher`   | Adds pepper (secret key) to password hashing |
| `DefaultPasswordValidator` | Validates passwords against policy rules     |
| `PasswordPolicy`           | Configurable password policy with rules      |
| `PwnedPasswordChecker`     | Checks passwords against Have I Been Pwned   |
| `PasswordStrengthMeter`    | Calculates password entropy and strength     |

## Password Hashing

### Argon2id (Recommended)

```php
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;

$hasher = DefaultPasswordHasher::argon2id();
$hash = $hasher->hash('password');

if ($hasher->verify('password', $hash)) {
    // Password is correct
}

if ($hasher->needsRehash($hash)) {
    // Re-hash with new parameters
    $newHash = $hasher->hash('password');
}
```

### High Security Configuration

```php
$hasher = DefaultPasswordHasher::highSecurity();
```

### With Pepper

A pepper adds an additional secret key that must be compromised separately from
the database.

```php
use Zappzarapp\Security\Password\Hashing\PepperedPasswordHasher;

$pepper = getenv('PASSWORD_PEPPER'); // 32+ bytes, stored separately
$hasher = new PepperedPasswordHasher($pepper);

$hash = $hasher->hash('password');
```

## Password Validation

### Basic Validation

```php
use Zappzarapp\Security\Password\Validation\DefaultPasswordValidator;

$validator = new DefaultPasswordValidator();
$result = $validator->validate('MyPassword123!');

if ($result->isValid()) {
    // Password meets policy
} else {
    foreach ($result->getViolations() as $violation) {
        echo $violation->getMessage();
    }
}
```

### Custom Policy

```php
use Zappzarapp\Security\Password\Policy\PasswordPolicy;
use Zappzarapp\Security\Password\Policy\Rules\MinLengthRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireDigitRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireSpecialCharRule;

$policy = new PasswordPolicy([
    new MinLengthRule(12),
    new RequireDigitRule(),
    new RequireSpecialCharRule(),
]);

$validator = new DefaultPasswordValidator($policy);
```

### Available Rules

| Rule                     | Description                 |
| ------------------------ | --------------------------- |
| `MinLengthRule`          | Minimum password length     |
| `MaxLengthRule`          | Maximum password length     |
| `RequireUppercaseRule`   | Requires uppercase letters  |
| `RequireLowercaseRule`   | Requires lowercase letters  |
| `RequireDigitRule`       | Requires numeric digits     |
| `RequireSpecialCharRule` | Requires special characters |

## Pwned Password Detection

Check if a password has been exposed in known data breaches using the Have I
Been Pwned API.

```php
use Zappzarapp\Security\Password\Pwned\PwnedPasswordChecker;
use Zappzarapp\Security\Password\Pwned\PwnedCheckerConfig;

$checker = new PwnedPasswordChecker();

if ($checker->isPwned('password123')) {
    // Password found in data breaches - reject it
}

// Get breach count
$count = $checker->getPwnedCount('password123');
```

### With Custom Config

```php
$config = new PwnedCheckerConfig(
    timeout: 5,
    threshold: 10  // Only flag if seen in 10+ breaches
);
$checker = new PwnedPasswordChecker($config);
```

## Password Strength

Calculate password entropy and strength level.

```php
use Zappzarapp\Security\Password\Strength\PasswordStrengthMeter;

$meter = new PasswordStrengthMeter();
$strength = $meter->measure('MyP@ssw0rd!');

echo $strength->getLevel()->name;    // STRONG, MEDIUM, WEAK, etc.
echo $strength->getEntropy();        // Entropy in bits
echo $strength->getScore();          // 0-100 score
```

## Security Considerations

1. **Use Argon2id** - It provides better resistance against GPU-based attacks
   than bcrypt
2. **Add a pepper** - Store it separately from your database (e.g., environment
   variable, secrets manager)
3. **Check for pwned passwords** - Reject passwords found in data breaches
4. **Enforce minimum length** - At least 12 characters for user passwords
5. **Clear sensitive data** - The library uses `sodium_memzero` when available
   to clear passwords from memory
