# Rate Limiting

Protect your application from brute force attacks and abuse using token bucket
or sliding window rate limiting.

## Quick Start

```php
use Zappzarapp\Security\RateLimiting\TokenBucket\TokenBucketLimiter;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;

$limiter = new TokenBucketLimiter(
    storage: new InMemoryStorage(),
    capacity: 10,      // Maximum burst
    refillRate: 1.0    // Tokens per second
);

$identifier = 'user:' . $userId;

if (!$limiter->consume($identifier)) {
    throw new \RuntimeException('Rate limit exceeded');
}
```

## Classes

| Class                  | Description                             |
| ---------------------- | --------------------------------------- |
| `TokenBucketLimiter`   | Token bucket algorithm (bursty traffic) |
| `SlidingWindowLimiter` | Sliding window algorithm (smooth rate)  |
| `InMemoryStorage`      | In-memory storage (single server)       |

## Algorithms

### Token Bucket

Best for APIs where occasional bursts are acceptable.

```php
use Zappzarapp\Security\RateLimiting\TokenBucket\TokenBucketLimiter;

$limiter = new TokenBucketLimiter(
    storage: $storage,
    capacity: 100,     // Can handle burst of 100 requests
    refillRate: 10.0   // Refills 10 tokens per second
);

// Consume 1 token
if ($limiter->consume($identifier)) {
    // Request allowed
}

// Consume multiple tokens (for expensive operations)
if ($limiter->consume($identifier, cost: 5)) {
    // Heavy operation allowed
}
```

### Sliding Window

Best for strict rate enforcement without bursts.

```php
use Zappzarapp\Security\RateLimiting\SlidingWindow\SlidingWindowLimiter;

$limiter = new SlidingWindowLimiter(
    storage: $storage,
    limit: 100,           // Max requests
    windowSize: 60        // Per 60 seconds
);

if ($limiter->attempt($identifier)) {
    // Within rate limit
}
```

## Identifiers

Choose the right identifier based on what you're protecting:

```php
// Per user (authenticated requests)
$identifier = 'user:' . $userId;

// Per IP (unauthenticated requests)
$identifier = 'ip:' . $_SERVER['REMOTE_ADDR'];

// Per endpoint
$identifier = 'endpoint:' . $requestPath . ':' . $userId;

// Per action
$identifier = 'login:' . $username;
```

## Response Headers

Include rate limit information in responses:

```php
$status = $limiter->getStatus($identifier);

header('X-RateLimit-Limit: ' . $status->getLimit());
header('X-RateLimit-Remaining: ' . $status->getRemaining());
header('X-RateLimit-Reset: ' . $status->getResetTime());
```

## Storage Backends

### In-Memory (Single Server)

```php
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;

$storage = new InMemoryStorage();
```

### Custom Storage (Redis, etc.)

Implement the storage interface for distributed rate limiting:

```php
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorageInterface;

class RedisRateLimitStorage implements RateLimitStorageInterface
{
    public function get(string $key): ?array
    {
        // Get from Redis
    }

    public function set(string $key, array $data, int $ttl): void
    {
        // Store in Redis
    }
}
```

## Use Cases

### Login Protection

```php
$loginLimiter = new SlidingWindowLimiter(
    storage: $storage,
    limit: 5,             // 5 attempts
    windowSize: 900       // Per 15 minutes
);

$identifier = 'login:' . $username;

if (!$loginLimiter->attempt($identifier)) {
    // Lock account or require CAPTCHA
    throw new RateLimitExceededException('Too many login attempts');
}
```

### API Rate Limiting

```php
$apiLimiter = new TokenBucketLimiter(
    storage: $storage,
    capacity: 1000,       // Burst capacity
    refillRate: 100.0     // 100 requests/second sustained
);

$identifier = 'api:' . $apiKey;

if (!$apiLimiter->consume($identifier)) {
    http_response_code(429);
    exit('Rate limit exceeded');
}
```

## Security Considerations

1. **Identify by multiple factors** - Combine user ID, IP, and fingerprint when
   possible
2. **Use distributed storage** - In-memory only works for single-server setups
3. **Log rate limit events** - Track for security monitoring
4. **Apply at multiple levels** - Global, per-user, and per-endpoint limits
5. **Fail securely** - If storage fails, default to blocking (not allowing)
