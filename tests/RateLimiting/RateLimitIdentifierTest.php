<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;

#[CoversClass(RateLimitIdentifier::class)]
final class RateLimitIdentifierTest extends TestCase
{
    public function testFromIp(): void
    {
        $identifier = RateLimitIdentifier::fromIp('192.168.1.1');

        $this->assertSame('ip:192.168.1.1', $identifier->value());
    }

    public function testFromIpWithIpv6(): void
    {
        $identifier = RateLimitIdentifier::fromIp('2001:db8::1');

        $this->assertSame('ip:2001:db8::1', $identifier->value());
    }

    public function testFromUserIdWithInt(): void
    {
        $identifier = RateLimitIdentifier::fromUserId(123);

        $this->assertSame('user:123', $identifier->value());
    }

    public function testFromUserIdWithString(): void
    {
        $identifier = RateLimitIdentifier::fromUserId('user-abc-123');

        $this->assertSame('user:user-abc-123', $identifier->value());
    }

    public function testFromApiKey(): void
    {
        $identifier = RateLimitIdentifier::fromApiKey('secret-api-key');

        // API key should be hashed
        $expectedHash = hash('sha256', 'secret-api-key');
        $this->assertSame('api:' . $expectedHash, $identifier->value());
    }

    public function testFromApiKeyHashesSameKeySameWay(): void
    {
        $identifier1 = RateLimitIdentifier::fromApiKey('my-key');
        $identifier2 = RateLimitIdentifier::fromApiKey('my-key');

        $this->assertSame($identifier1->value(), $identifier2->value());
    }

    public function testFromApiKeyHashesDifferentKeysDifferently(): void
    {
        $identifier1 = RateLimitIdentifier::fromApiKey('key-1');
        $identifier2 = RateLimitIdentifier::fromApiKey('key-2');

        $this->assertNotSame($identifier1->value(), $identifier2->value());
    }

    public function testCustom(): void
    {
        $identifier = RateLimitIdentifier::custom('custom_type', 'custom_value');

        $this->assertSame('custom_type:custom_value', $identifier->value());
    }

    public function testCustomWithEmptyType(): void
    {
        $identifier = RateLimitIdentifier::custom('', 'value');

        $this->assertSame(':value', $identifier->value());
    }

    public function testCustomWithEmptyValue(): void
    {
        $identifier = RateLimitIdentifier::custom('type', '');

        $this->assertSame('type:', $identifier->value());
    }

    public function testComposite(): void
    {
        $identifiers = [
            RateLimitIdentifier::fromIp('192.168.1.1'),
            RateLimitIdentifier::fromUserId(123),
        ];

        $composite = RateLimitIdentifier::composite($identifiers);

        $this->assertSame('ip:192.168.1.1|user:123', $composite->value());
    }

    public function testCompositeWithSingleIdentifier(): void
    {
        $identifiers = [
            RateLimitIdentifier::fromIp('192.168.1.1'),
        ];

        $composite = RateLimitIdentifier::composite($identifiers);

        $this->assertSame('ip:192.168.1.1', $composite->value());
    }

    public function testCompositeWithEmptyArray(): void
    {
        $composite = RateLimitIdentifier::composite([]);

        $this->assertSame('', $composite->value());
    }

    public function testCompositeWithMultipleIdentifiers(): void
    {
        $identifiers = [
            RateLimitIdentifier::fromIp('10.0.0.1'),
            RateLimitIdentifier::fromUserId('admin'),
            RateLimitIdentifier::custom('endpoint', '/api/users'),
        ];

        $composite = RateLimitIdentifier::composite($identifiers);

        $this->assertSame('ip:10.0.0.1|user:admin|endpoint:/api/users', $composite->value());
    }

    public function testFromRequestWithIpOnly(): void
    {
        $identifier = RateLimitIdentifier::fromRequest('192.168.1.1');

        $this->assertSame('ip:192.168.1.1', $identifier->value());
    }

    public function testFromRequestWithIpAndUserId(): void
    {
        $identifier = RateLimitIdentifier::fromRequest('192.168.1.1', 123);

        $this->assertSame('ip:192.168.1.1|user:123', $identifier->value());
    }

    public function testFromRequestWithIpAndStringUserId(): void
    {
        $identifier = RateLimitIdentifier::fromRequest('10.0.0.1', 'user-uuid');

        $this->assertSame('ip:10.0.0.1|user:user-uuid', $identifier->value());
    }

    public function testFromRequestWithNullIpUsesUnknown(): void
    {
        // Unset REMOTE_ADDR if set
        $originalRemoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
        unset($_SERVER['REMOTE_ADDR']);

        try {
            $identifier = RateLimitIdentifier::fromRequest(null, 123);

            $this->assertSame('ip:unknown|user:123', $identifier->value());
        } finally {
            // Restore original value
            if ($originalRemoteAddr !== null) {
                $_SERVER['REMOTE_ADDR'] = $originalRemoteAddr;
            }
        }
    }

    public function testFromRequestUsesRemoteAddr(): void
    {
        $originalRemoteAddr           = $_SERVER['REMOTE_ADDR'] ?? null;
        $_SERVER['REMOTE_ADDR']       = '172.16.0.1';

        try {
            $identifier = RateLimitIdentifier::fromRequest();

            $this->assertSame('ip:172.16.0.1', $identifier->value());
        } finally {
            if ($originalRemoteAddr !== null) {
                $_SERVER['REMOTE_ADDR'] = $originalRemoteAddr;
            } else {
                unset($_SERVER['REMOTE_ADDR']);
            }
        }
    }

    public function testFromRequestWithNullIpAndNullUserId(): void
    {
        $originalRemoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
        unset($_SERVER['REMOTE_ADDR']);

        try {
            $identifier = RateLimitIdentifier::fromRequest();

            $this->assertSame('ip:unknown', $identifier->value());
        } finally {
            if ($originalRemoteAddr !== null) {
                $_SERVER['REMOTE_ADDR'] = $originalRemoteAddr;
            }
        }
    }

    public function testValueIsImmutable(): void
    {
        $identifier = RateLimitIdentifier::fromIp('192.168.1.1');

        $value1 = $identifier->value();
        $value2 = $identifier->value();

        $this->assertSame($value1, $value2);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function specialCharacterIpProvider(): array
    {
        return [
            'ipv4'                 => ['127.0.0.1', 'ip:127.0.0.1'],
            'ipv4 with port'       => ['192.168.1.1:8080', 'ip:192.168.1.1:8080'],
            'ipv6 full'            => ['2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'ip:2001:0db8:85a3:0000:0000:8a2e:0370:7334'],
            'ipv6 compressed'      => ['::1', 'ip:::1'],
            'ipv6 with zone'       => ['fe80::1%eth0', 'ip:fe80::1%eth0'],
        ];
    }

    #[DataProvider('specialCharacterIpProvider')]
    public function testFromIpWithSpecialFormats(string $ip, string $expected): void
    {
        $identifier = RateLimitIdentifier::fromIp($ip);

        $this->assertSame($expected, $identifier->value());
    }

    public function testFromIpWithEmptyString(): void
    {
        $identifier = RateLimitIdentifier::fromIp('');

        $this->assertSame('ip:', $identifier->value());
    }

    public function testFromUserIdWithZero(): void
    {
        $identifier = RateLimitIdentifier::fromUserId(0);

        $this->assertSame('user:0', $identifier->value());
    }

    public function testFromUserIdWithNegative(): void
    {
        $identifier = RateLimitIdentifier::fromUserId(-1);

        $this->assertSame('user:-1', $identifier->value());
    }

    public function testFromApiKeyWithEmptyString(): void
    {
        $identifier = RateLimitIdentifier::fromApiKey('');

        $expectedHash = hash('sha256', '');
        $this->assertSame('api:' . $expectedHash, $identifier->value());
    }

    public function testCompositeOfComposites(): void
    {
        $inner1 = RateLimitIdentifier::composite([
            RateLimitIdentifier::fromIp('1.1.1.1'),
            RateLimitIdentifier::fromUserId(1),
        ]);

        $inner2 = RateLimitIdentifier::composite([
            RateLimitIdentifier::fromIp('2.2.2.2'),
            RateLimitIdentifier::fromUserId(2),
        ]);

        $outer = RateLimitIdentifier::composite([$inner1, $inner2]);

        $this->assertSame('ip:1.1.1.1|user:1|ip:2.2.2.2|user:2', $outer->value());
    }

    // =========================================================================
    // Escaping Tests (kill str_replace mutations)
    // =========================================================================

    public function testCustomEscapesColonInType(): void
    {
        // Colon is the TYPE_DELIMITER, must be escaped
        $identifier = RateLimitIdentifier::custom('type:with:colons', 'value');

        $this->assertSame('type\\:with\\:colons:value', $identifier->value());
    }

    public function testCustomEscapesColonInValue(): void
    {
        $identifier = RateLimitIdentifier::custom('type', 'value:with:colons');

        $this->assertSame('type:value\\:with\\:colons', $identifier->value());
    }

    public function testCustomEscapesPipeInType(): void
    {
        // Pipe is the COMPOSITE_DELIMITER, must be escaped
        $identifier = RateLimitIdentifier::custom('type|with|pipes', 'value');

        $this->assertSame('type\\|with\\|pipes:value', $identifier->value());
    }

    public function testCustomEscapesPipeInValue(): void
    {
        $identifier = RateLimitIdentifier::custom('type', 'value|with|pipes');

        $this->assertSame('type:value\\|with\\|pipes', $identifier->value());
    }

    public function testCustomEscapesBackslashFirst(): void
    {
        // Backslash must be escaped BEFORE other delimiters to prevent double-escaping
        $identifier = RateLimitIdentifier::custom('type', 'back\\slash');

        $this->assertSame('type:back\\\\slash', $identifier->value());
    }

    public function testCustomEscapesBackslashBeforeColon(): void
    {
        // Test that backslash followed by colon is handled correctly
        // Input: "a\:b" -> Output should be "a\\:b" (backslash escaped, colon escaped)
        // NOT "a\\\:b" (which would happen if order was wrong)
        $identifier = RateLimitIdentifier::custom('type', 'a\\:b');

        // Backslash becomes \\, then : becomes \: = a\\:\:b? No...
        // Actually: str_replace processes all at once with arrays
        // 'a\:b' -> backslash escaped: 'a\\:b' -> colon escaped: 'a\\\:b'
        // Hmm, let me think about this more carefully...
        // With the replacement order ['\\' => '\\\\', ':' => '\:']:
        // Input 'a\:b': first \ -> \\, result: 'a\\:b'
        // Then : -> \:, result: 'a\\\:b'
        $this->assertSame('type:a\\\\\\:b', $identifier->value());
    }

    public function testCustomWithAllSpecialCharacters(): void
    {
        // Test combination of all special characters
        $identifier = RateLimitIdentifier::custom('t:y|p\\e', 'v:a|l\\ue');

        // Type escaping: t\:y\|p\\e
        // Value escaping: v\:a\|l\\ue
        $this->assertSame('t\\:y\\|p\\\\e:v\\:a\\|l\\\\ue', $identifier->value());
    }
}
