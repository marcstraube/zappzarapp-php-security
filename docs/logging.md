# Security Audit Logging

Log security-related events with correlation IDs for tracking and auditing.

## Quick Start

```php
use Zappzarapp\Security\Logging\SecurityAuditLogger;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityEventType;

$logger = new SecurityAuditLogger($psrLogger);

// Log a security event
$event = new SecurityEvent(
    SecurityEventType::AUTHENTICATION_FAILURE,
    ['username' => 'john', 'ip' => $_SERVER['REMOTE_ADDR']]
);
$logger->securityEvent($event);
```

## Classes

| Class                 | Description                      |
| --------------------- | -------------------------------- |
| `SecurityAuditLogger` | PSR-3 compatible security logger |
| `SecurityEvent`       | Security event value object      |
| `SecurityEventType`   | Enum of security event types     |

## Event Types

| Type                      | Severity | Description                    |
| ------------------------- | -------- | ------------------------------ |
| `AUTHENTICATION_FAILURE`  | Alert    | Failed login attempt           |
| `AUTHENTICATION_SUCCESS`  | Info     | Successful login               |
| `CSRF_VALIDATION_FAILURE` | Alert    | CSRF token mismatch            |
| `RATE_LIMIT_WARNING`      | Warning  | Approaching rate limit         |
| `RATE_LIMIT_EXCEEDED`     | Alert    | Rate limit exceeded            |
| `PATH_TRAVERSAL_ATTEMPT`  | Critical | Path traversal attack detected |
| `XSS_ATTEMPT_BLOCKED`     | Warning  | XSS payload blocked            |
| `UNAUTHORIZED_ACCESS`     | Alert    | Access to restricted resource  |

## Correlation IDs

Track related events across requests:

```php
// Auto-generated correlation ID
$logger = new SecurityAuditLogger($psrLogger);
echo $logger->correlationId(); // 32-character hex string

// Custom correlation ID
$logger = new SecurityAuditLogger($psrLogger, 'request-' . uniqid());

// Create new logger with different correlation ID
$newLogger = $logger->withCorrelationId('session-specific-id');
```

## Logging Levels

```php
// Standard PSR-3 methods with security context
$logger->warning('Suspicious activity', ['ip' => $ip]);
$logger->alert('Brute force detected', ['attempts' => 10]);
$logger->critical('Security breach', ['details' => $details]);

// All logs automatically include:
// - correlation_id
// - security_component: 'zappzarapp/security'
// - timestamp
```

## Security Events

### Creating Events

```php
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityEventType;

$event = new SecurityEvent(
    SecurityEventType::AUTHENTICATION_FAILURE,
    [
        'username' => $username,
        'ip_address' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
    ],
    correlationId: 'custom-correlation-id'  // Optional
);

$logger->securityEvent($event);
```

### Event Properties

```php
$event = new SecurityEvent(SecurityEventType::RATE_LIMIT_EXCEEDED, $context);

$event->type;           // SecurityEventType enum
$event->context;        // Additional data
$event->correlationId;  // Correlation ID (optional)
$event->timestamp;      // DateTimeImmutable
```

## Integration

### With Monolog

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$monolog = new Logger('security');
$monolog->pushHandler(new StreamHandler('/var/log/security.log', Logger::WARNING));

$logger = new SecurityAuditLogger($monolog);
```

### With Symfony

```php
use Psr\Log\LoggerInterface;

class SecurityEventSubscriber
{
    public function __construct(
        private SecurityAuditLogger $logger
    ) {}

    public function onAuthenticationFailure(AuthenticationFailureEvent $event): void
    {
        $this->logger->securityEvent(new SecurityEvent(
            SecurityEventType::AUTHENTICATION_FAILURE,
            ['username' => $event->getUsername()]
        ));
    }
}
```

## Log Format

All logs include consistent structure:

```json
{
  "message": "Rate limit has been exceeded",
  "context": {
    "event_type": "security.rate_limit.exceeded",
    "identifier": "user:123",
    "correlation_id": "abc123def456",
    "security_component": "zappzarapp/security",
    "event_timestamp": "2024-01-15T10:30:00+00:00"
  },
  "level": "alert"
}
```

## Security Considerations

1. **Don't log sensitive data** - Never log passwords, tokens, or personal data
2. **Log client context** - Include IP, user agent for forensics
3. **Use correlation IDs** - Track events across requests/services
4. **Alert on critical events** - Set up alerts for critical security events
5. **Retain logs appropriately** - Balance compliance needs with privacy
6. **Protect log files** - Logs may contain sensitive information
