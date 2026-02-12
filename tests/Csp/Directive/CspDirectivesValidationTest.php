<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives input validation
 */
final class CspDirectivesValidationTest extends TestCase
{
    // Empty Value Validation
    public function testThrowsForEmptyDefaultSrc(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('default-src cannot be empty');

        new CspDirectives(defaultSrc: '');
    }

    public function testThrowsForWhitespaceOnlyDefaultSrc(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('default-src cannot be empty');

        new CspDirectives(defaultSrc: '   ');
    }

    // Semicolon Injection Prevention
    public function testThrowsForSemicolonInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('semicolon');

        new CspDirectives(defaultSrc: "'self'; evil-script-src");
    }

    public function testThrowsForSemicolonInScriptSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('script-src');

        new CspDirectives(scriptSrc: "'self'; evil");
    }

    public function testThrowsForSemicolonInStyleSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('style-src');

        new CspDirectives(styleSrc: "'self'; evil");
    }

    // Newline Injection Prevention
    public function testThrowsForNewlineInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('control character');

        new CspDirectives(defaultSrc: "'self'\nevil");
    }

    public function testThrowsForCarriageReturnInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('control character');

        new CspDirectives(defaultSrc: "'self'\revil");
    }

    public function testThrowsForCrLfInDefaultSrc(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('control character');

        new CspDirectives(defaultSrc: "'self'\r\nevil");
    }

    // WebSocket Host Validation
    public function testThrowsForInvalidWebSocketHostWithoutPort(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('WebSocket host format is invalid');

        new CspDirectives(websocketHost: 'example.com');
    }

    public function testThrowsForInvalidWebSocketHostWithProtocol(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('WebSocket host format is invalid');

        new CspDirectives(websocketHost: 'wss://example.com:443');
    }

    public function testThrowsForInvalidWebSocketHostWithPath(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('WebSocket host format is invalid');

        new CspDirectives(websocketHost: 'example.com:443/path');
    }

    public function testThrowsForInvalidWebSocketHostEmpty(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('WebSocket host format is invalid');

        new CspDirectives(websocketHost: '');
    }

    // Valid WebSocket Hosts
    public function testAcceptsValidWebSocketHostWithDomain(): void
    {
        $directives = new CspDirectives(websocketHost: 'example.com:443');

        $this->assertSame('example.com:443', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithSubdomain(): void
    {
        $directives = new CspDirectives(websocketHost: 'ws.api.example.com:8080');

        $this->assertSame('ws.api.example.com:8080', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithIp(): void
    {
        $directives = new CspDirectives(websocketHost: '192.168.1.100:5173');

        $this->assertSame('192.168.1.100:5173', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithLocalhost(): void
    {
        $directives = new CspDirectives(websocketHost: 'localhost:8443');

        $this->assertSame('localhost:8443', $directives->websocketHost);
    }

    // WebSocket Port Range Validation
    public function testThrowsForWebSocketPortZero(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('port 0 must be between 1 and 65535');

        new CspDirectives(websocketHost: 'localhost:0');
    }

    public function testThrowsForWebSocketPortAboveMax(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('port 65536 must be between 1 and 65535');

        new CspDirectives(websocketHost: 'localhost:65536');
    }

    public function testThrowsForWebSocketPortWayAboveMax(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('port 99999 must be between 1 and 65535');

        new CspDirectives(websocketHost: 'example.com:99999');
    }

    public function testAcceptsWebSocketPortOne(): void
    {
        $directives = new CspDirectives(websocketHost: 'localhost:1');

        $this->assertSame('localhost:1', $directives->websocketHost);
    }

    public function testAcceptsWebSocketPortMax(): void
    {
        $directives = new CspDirectives(websocketHost: 'localhost:65535');

        $this->assertSame('localhost:65535', $directives->websocketHost);
    }

    // Valid Directive Values
    public function testAcceptsValidDefaultSrc(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self' https://example.com https://cdn.example.com");

        $this->assertSame("'self' https://example.com https://cdn.example.com", $directives->defaultSrc);
    }

    public function testAcceptsValidScriptSrc(): void
    {
        // Use LENIENT policy to avoid policy conflict warning
        $directives = new CspDirectives(
            scriptSrc: "'self' 'unsafe-inline' https://scripts.example.com",
            securityPolicy: SecurityPolicy::LENIENT
        );

        $this->assertSame("'self' 'unsafe-inline' https://scripts.example.com", $directives->scriptSrc);
    }

    public function testAcceptsValidStyleSrc(): void
    {
        // Use LENIENT policy to avoid policy conflict warning
        $directives = new CspDirectives(
            styleSrc: "'self' 'unsafe-inline' https://fonts.googleapis.com",
            securityPolicy: SecurityPolicy::LENIENT
        );

        $this->assertSame("'self' 'unsafe-inline' https://fonts.googleapis.com", $directives->styleSrc);
    }

    // Policy Conflict Warning Tests
        public function testWarnsOnStrictWithUnsafeInlineInScriptSrc(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            scriptSrc: "'self' 'unsafe-inline'",
            securityPolicy: SecurityPolicy::STRICT
        );

        restore_error_handler();

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString("'unsafe-inline' in script-src", $warnings[0]);
    }

        public function testWarnsOnStrictWithUnsafeEvalInScriptSrc(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            scriptSrc: "'self' 'unsafe-eval'",
            securityPolicy: SecurityPolicy::STRICT
        );

        restore_error_handler();

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString("'unsafe-eval' in script-src", $warnings[0]);
    }

        public function testWarnsOnStrictWithUnsafeInlineInStyleSrc(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            styleSrc: "'self' 'unsafe-inline'",
            securityPolicy: SecurityPolicy::STRICT
        );

        restore_error_handler();

        $this->assertCount(1, $warnings);
        $this->assertStringContainsString("'unsafe-inline' in style-src", $warnings[0]);
    }

        public function testNoWarningOnLenientWithUnsafeInline(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            scriptSrc: "'self' 'unsafe-inline'",
            securityPolicy: SecurityPolicy::LENIENT
        );

        restore_error_handler();

        $this->assertCount(0, $warnings);
    }

        public function testNoWarningOnStrictWithoutUnsafeDirectives(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            scriptSrc: "'self' https://scripts.example.com",
            securityPolicy: SecurityPolicy::STRICT
        );

        restore_error_handler();

        $this->assertCount(0, $warnings);
    }

        public function testMultipleWarningsOnStrictWithMultipleConflicts(): void
    {
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            if ($errno === E_USER_WARNING) {
                $warnings[] = $errstr;
            }

            return true;
        });

        new CspDirectives(
            scriptSrc: "'self' 'unsafe-inline' 'unsafe-eval'",
            styleSrc: "'self' 'unsafe-inline'",
            securityPolicy: SecurityPolicy::STRICT
        );

        restore_error_handler();

        $this->assertCount(3, $warnings);
    }
}
