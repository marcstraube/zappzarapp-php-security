<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Pwned;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\Password\Exception\PwnedPasswordException;
use Zappzarapp\Security\Password\Pwned\HttpClientInterface;
use Zappzarapp\Security\Password\Pwned\PwnedCheckerConfig;
use Zappzarapp\Security\Password\Pwned\PwnedPasswordChecker;
#[CoversClass(PwnedPasswordChecker::class)]
final class PwnedPasswordCheckerTest extends TestCase
{
    public function testCheckReturnsZeroWhenApiUnavailableInFailOpenMode(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = new PwnedCheckerConfig(failClosed: false);
        $checker = new PwnedPasswordChecker($client, $config);

        $result = $checker->check('password123');

        $this->assertSame(0, $result);
    }

    public function testCheckReturnsFailClosedCountWhenApiUnavailableInFailClosedMode(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = (new PwnedCheckerConfig())->withFailClosed();
        $checker = new PwnedPasswordChecker($client, $config);

        $result = $checker->check('password123');

        $this->assertSame(PwnedCheckerConfig::FAIL_CLOSED_COUNT, $result);
    }

    public function testIsCompromisedReturnsTrueWhenApiUnavailableInFailClosedMode(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = (new PwnedCheckerConfig())->withFailClosed();
        $checker = new PwnedPasswordChecker($client, $config);

        $this->assertTrue($checker->isCompromised('anypassword'));
    }

    public function testIsCompromisedReturnsFalseWhenApiUnavailableInFailOpenMode(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = new PwnedCheckerConfig(failClosed: false);
        $checker = new PwnedPasswordChecker($client, $config);

        $this->assertFalse($checker->isCompromised('anypassword'));
    }

    public function testCheckReturnsOccurrencesWhenPasswordFound(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        // SHA1 of 'password' is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // First 5 chars: 5BAA6, suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\nABCDEF:100");

        $checker = new PwnedPasswordChecker($client);

        $result = $checker->check('password');

        $this->assertSame(12345, $result);
    }

    public function testCheckReturnsZeroWhenPasswordNotFound(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("ABCDEF1234567890ABCDEF1234567890ABC:100\r\nXYZ123:50");

        $checker = new PwnedPasswordChecker($client);

        $result = $checker->check('my-unique-strong-password-12345');

        $this->assertSame(0, $result);
    }

    public function testIsCompromisedLogsWhenCompromisedPasswordDetected(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:500\r\n");

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('alert')
            ->with(
                'Compromised password detected',
                $this->callback(fn(array $context): bool => $context['occurrences'] === 500
                    && $context['min_occurrences'] === 1
                    && $context['fail_closed_mode'] === false)
            );

        $checker = new PwnedPasswordChecker($client, new PwnedCheckerConfig(), $logger);

        $checker->isCompromised('password');
    }

    public function testIsCompromisedLogsFailClosedModeCorrectly(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('alert')
            ->with(
                'Compromised password detected',
                $this->callback(fn(array $context): bool => $context['occurrences'] === PHP_INT_MAX
                    && $context['fail_closed_mode'] === true)
            );

        $config  = (new PwnedCheckerConfig())->withFailClosed();
        $checker = new PwnedPasswordChecker($client, $config, $logger);

        $checker->isCompromised('anypassword');
    }

    public function testIsCompromisedDoesNotLogWhenPasswordNotCompromised(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->never())->method('alert');

        $checker = new PwnedPasswordChecker($client, new PwnedCheckerConfig(), $logger);

        $checker->isCompromised('unique-password-xyz');
    }

    public function testCheckAndThrowDoesNotThrowWhenPasswordNotCompromised(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $checker = new PwnedPasswordChecker($client);

        // Should not throw
        $checker->checkAndThrow('unique-password-xyz');
        $this->assertTrue(true); // Assertion to confirm no exception
    }

    public function testCheckAndThrowThrowsWhenPasswordCompromised(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        // SHA1 of 'password' suffix
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n");

        $checker = new PwnedPasswordChecker($client);

        $this->expectException(PwnedPasswordException::class);
        $this->expectExceptionMessage('Password has been exposed in 12345 data breaches');

        $checker->checkAndThrow('password');
    }

    public function testCheckAndThrowRespectsMinOccurrences(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\r\n");

        // Set minOccurrences to 10, so 5 should not trigger exception
        $config  = new PwnedCheckerConfig(minOccurrences: 10);
        $checker = new PwnedPasswordChecker($client, $config);

        // Should not throw because 5 < 10
        $checker->checkAndThrow('password');
        $this->assertTrue(true);
    }

    public function testCheckAndThrowThrowsWhenExactlyAtMinOccurrences(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\r\n");

        $config  = new PwnedCheckerConfig(minOccurrences: 10);
        $checker = new PwnedPasswordChecker($client, $config);

        $this->expectException(PwnedPasswordException::class);

        $checker->checkAndThrow('password');
    }

    public function testCheckAndThrowThrowsInFailClosedMode(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = (new PwnedCheckerConfig())->withFailClosed();
        $checker = new PwnedPasswordChecker($client, $config);

        $this->expectException(PwnedPasswordException::class);

        $checker->checkAndThrow('anypassword');
    }

    public function testCheckAndThrowDoesNotThrowInFailOpenModeWhenApiUnavailable(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $config  = new PwnedCheckerConfig(failClosed: false);
        $checker = new PwnedPasswordChecker($client, $config);

        // Should not throw in fail-open mode
        $checker->checkAndThrow('anypassword');
        $this->assertTrue(true);
    }

    public function testCheckAndThrowExceptionContainsCorrectOccurrences(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:999\r\n");

        $checker = new PwnedPasswordChecker($client);

        try {
            $checker->checkAndThrow('password');
            $this->fail('Expected PwnedPasswordException');
        } catch (PwnedPasswordException $e) {
            $this->assertSame(999, $e->occurrences());
        }
    }
}
