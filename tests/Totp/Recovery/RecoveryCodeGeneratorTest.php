<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp\Recovery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Exception\InvalidRecoveryCodeException;
use Zappzarapp\Security\Totp\Recovery\RecoveryCode;
use Zappzarapp\Security\Totp\Recovery\RecoveryCodeGenerator;

#[CoversClass(RecoveryCodeGenerator::class)]
#[CoversClass(InvalidRecoveryCodeException::class)]
#[UsesClass(RecoveryCode::class)]
#[UsesClass(SecretValue::class)]
final class RecoveryCodeGeneratorTest extends TestCase
{
    private RecoveryCodeGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new RecoveryCodeGenerator();
    }

    #[Test]
    public function testGeneratesTenCodesByDefault(): void
    {
        $this->assertCount(10, $this->generator->generate());
    }

    #[Test]
    public function testGeneratesRequestedCount(): void
    {
        $this->assertCount(1, $this->generator->generate(1));
        $this->assertCount(100, $this->generator->generate(100));
    }

    #[Test]
    public function testCodesMatchDocumentedFormat(): void
    {
        foreach ($this->generator->generate(5) as $code) {
            $this->assertMatchesRegularExpression(
                '/^[a-hj-km-np-z2-9]{4}(-[a-hj-km-np-z2-9]{4}){3}$/',
                $code->reveal()
            );
        }
    }

    #[Test]
    public function testCodesNeverContainLookAlikeCharacters(): void
    {
        foreach ($this->generator->generate(5) as $code) {
            $this->assertDoesNotMatchRegularExpression('/[ilo01]/', $code->reveal());
        }
    }

    #[Test]
    public function testCodesAreUnique(): void
    {
        $revealed = array_map(
            static fn (RecoveryCode $code): string => $code->reveal(),
            $this->generator->generate()
        );

        $this->assertSame($revealed, array_values(array_unique($revealed)));
    }

    #[Test]
    public function testEveryAlphabetCharacterAppears(): void
    {
        $characters = '';

        for ($run = 0; $run < 5; $run++) {
            foreach ($this->generator->generate(100) as $code) {
                $characters .= $code->normalized();
            }
        }

        foreach (str_split(RecoveryCodeGenerator::ALPHABET) as $character) {
            $this->assertStringContainsString($character, $characters);
        }
    }

    #[Test]
    public function testRejectsZeroCount(): void
    {
        $this->expectException(InvalidRecoveryCodeException::class);
        $this->expectExceptionMessage('Recovery code count must be between 1 and 100, got 0');

        $this->generator->generate(0);
    }

    #[Test]
    public function testRejectsExcessiveCount(): void
    {
        $this->expectException(InvalidRecoveryCodeException::class);
        $this->expectExceptionMessage('Recovery code count must be between 1 and 100, got 101');

        $this->generator->generate(101);
    }
}
