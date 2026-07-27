<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use stdClass;
use Zappzarapp\Security\Session\SessionConfig;
use Zappzarapp\Security\Session\SessionContext;
use Zappzarapp\Security\Session\SessionFingerprint;
use Zappzarapp\Security\Session\SessionGuard;
use Zappzarapp\Security\Session\SessionValidationResult;

#[CoversClass(SessionGuard::class)]
#[UsesClass(SessionConfig::class)]
#[UsesClass(SessionContext::class)]
#[UsesClass(SessionFingerprint::class)]
final class SessionGuardTest extends TestCase
{
    private const string METADATA_KEY = '_zappzarapp_session_security';

    private const int NOW = 1_800_000_000;

    private SessionContext $context;

    protected function setUp(): void
    {
        $this->context = new SessionContext('192.0.2.10', 'ExampleBrowser/1.0');
    }

    #[Test]
    public function testInitializeBindsSecurityMetadata(): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [];

        $guard->initialize($session, $this->context);

        $this->assertSame(
            [
                'created_at'    => self::NOW,
                'last_activity' => self::NOW,
                'fingerprint'   => (new SessionFingerprint(new SessionConfig()))->compute($this->context),
            ],
            $session[self::METADATA_KEY]
        );
    }

    #[Test]
    public function testValidatePassesFreshSession(): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [];
        $guard->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::VALID,
            $guard->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateWorksWithSystemClock(): void
    {
        $guard   = new SessionGuard();
        $session = [];
        $guard->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::VALID,
            $guard->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateRefreshesIdleTimer(): void
    {
        $session = [];
        $this->guardAt(self::NOW)->initialize($session, $this->context);

        $later = $this->guardAt(self::NOW + 600);
        $later->validate($session, $this->context);

        $this->assertSame(self::NOW + 600, $this->metadata($session)['last_activity']);
        $this->assertSame(self::NOW, $this->metadata($session)['created_at']);
    }

    #[Test]
    public function testValidateRejectsUninitializedSession(): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [];

        $this->assertSame(
            SessionValidationResult::UNINITIALIZED,
            $guard->validate($session, $this->context)
        );
    }

    #[DataProvider('malformedMetadataProvider')]
    #[Test]
    public function testValidateRejectsMalformedMetadata(mixed $metadata): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [self::METADATA_KEY => $metadata];

        $this->assertSame(
            SessionValidationResult::UNINITIALIZED,
            $guard->validate($session, $this->context)
        );
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function malformedMetadataProvider(): array
    {
        return [
            'not an array'         => ['tampered'],
            'object'               => [new stdClass()],
            'empty array'          => [[]],
            'missing fingerprint'  => [['created_at' => self::NOW, 'last_activity' => self::NOW]],
            'string timestamps'    => [['created_at' => 'now', 'last_activity' => self::NOW, 'fingerprint' => 'abc']],
            'float last activity'  => [['created_at' => self::NOW, 'last_activity' => 1.5, 'fingerprint' => 'abc']],
            'array fingerprint'    => [['created_at' => self::NOW, 'last_activity' => self::NOW, 'fingerprint' => []]],
        ];
    }

    #[Test]
    public function testValidateRejectsChangedUserAgent(): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [];
        $guard->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::FINGERPRINT_MISMATCH,
            $guard->validate($session, new SessionContext('192.0.2.10', 'OtherBrowser/9.9'))
        );
    }

    #[Test]
    public function testValidateAcceptsChangedIpByDefault(): void
    {
        $guard   = $this->guardAt(self::NOW);
        $session = [];
        $guard->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::VALID,
            $guard->validate($session, new SessionContext('198.51.100.7', 'ExampleBrowser/1.0'))
        );
    }

    #[Test]
    public function testValidateRejectsChangedIpWhenBound(): void
    {
        $config  = new SessionConfig(bindIpAddress: true);
        $session = [];
        $this->guardAt(self::NOW, $config)->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::FINGERPRINT_MISMATCH,
            $this->guardAt(self::NOW, $config)->validate(
                $session,
                new SessionContext('198.51.100.7', 'ExampleBrowser/1.0')
            )
        );
    }

    #[Test]
    public function testValidateAcceptsSessionAtIdleTimeoutBoundary(): void
    {
        $session = [];
        $this->guardAt(self::NOW)->initialize($session, $this->context);

        $atBoundary = $this->guardAt(self::NOW + 1800);

        $this->assertSame(
            SessionValidationResult::VALID,
            $atBoundary->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateRejectsSessionPastIdleTimeout(): void
    {
        $session = [];
        $this->guardAt(self::NOW)->initialize($session, $this->context);

        $pastBoundary = $this->guardAt(self::NOW + 1801);

        $this->assertSame(
            SessionValidationResult::IDLE_TIMEOUT_EXCEEDED,
            $pastBoundary->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateAcceptsSessionAtAbsoluteTimeoutBoundary(): void
    {
        $config  = new SessionConfig(idleTimeout: 43200, absoluteTimeout: 43200);
        $session = [];
        $this->guardAt(self::NOW, $config)->initialize($session, $this->context);

        $this->assertSame(
            SessionValidationResult::VALID,
            $this->guardAt(self::NOW + 43200, $config)->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateRejectsSessionPastAbsoluteTimeout(): void
    {
        $config  = new SessionConfig(idleTimeout: 43201, absoluteTimeout: 43201);
        $session = [];
        $this->guardAt(self::NOW, $config)->initialize($session, $this->context);

        // Keep activity fresh so only the absolute timeout can trigger
        $this->guardAt(self::NOW + 43200, $config)->validate($session, $this->context);

        $this->assertSame(
            SessionValidationResult::ABSOLUTE_TIMEOUT_EXCEEDED,
            $this->guardAt(self::NOW + 43202, $config)->validate($session, $this->context)
        );
    }

    #[Test]
    public function testValidateFailureLeavesMetadataUntouched(): void
    {
        $session = [];
        $this->guardAt(self::NOW)->initialize($session, $this->context);

        $this->guardAt(self::NOW + 1801)->validate($session, $this->context);

        $this->assertSame(self::NOW, $this->metadata($session)['last_activity']);
    }

    #[Test]
    public function testInitializeAfterRegenerationResetsClock(): void
    {
        $session = [];
        $this->guardAt(self::NOW)->initialize($session, $this->context);

        // Privilege change at NOW + 600: caller regenerates the ID and re-initializes
        $this->guardAt(self::NOW + 600)->initialize($session, $this->context);

        $this->assertSame(self::NOW + 600, $this->metadata($session)['created_at']);
        $this->assertSame(self::NOW + 600, $this->metadata($session)['last_activity']);
    }

    private function guardAt(int $timestamp, ?SessionConfig $config = null): SessionGuard
    {
        $clock = new class($timestamp) implements ClockInterface {
            public function __construct(private readonly int $timestamp)
            {
            }

            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('@' . $this->timestamp);
            }
        };

        return new SessionGuard($config ?? new SessionConfig(), $clock);
    }

    /**
     * @param array<array-key, mixed> $session
     *
     * @return array<array-key, mixed>
     */
    private function metadata(array $session): array
    {
        $metadata = $session[self::METADATA_KEY];
        $this->assertIsArray($metadata);

        return $metadata;
    }
}
