<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\CspValue;

final class CspValueTest extends TestCase
{
    // Enum Values
    public function testSelfValue(): void
    {
        $this->assertSame("'self'", CspValue::SELF->value);
    }

    public function testNoneValue(): void
    {
        $this->assertSame("'none'", CspValue::NONE->value);
    }

    public function testUnsafeInlineValue(): void
    {
        $this->assertSame("'unsafe-inline'", CspValue::UNSAFE_INLINE->value);
    }

    public function testUnsafeEvalValue(): void
    {
        $this->assertSame("'unsafe-eval'", CspValue::UNSAFE_EVAL->value);
    }

    public function testStrictDynamicValue(): void
    {
        $this->assertSame("'strict-dynamic'", CspValue::STRICT_DYNAMIC->value);
    }

    public function testDataValue(): void
    {
        $this->assertSame('data:', CspValue::DATA->value);
    }

    public function testBlobValue(): void
    {
        $this->assertSame('blob:', CspValue::BLOB->value);
    }

    public function testMediastreamValue(): void
    {
        $this->assertSame('mediastream:', CspValue::MEDIASTREAM->value);
    }

    public function testHttpsValue(): void
    {
        $this->assertSame('https:', CspValue::HTTPS->value);
    }

    public function testWssValue(): void
    {
        $this->assertSame('wss:', CspValue::WSS->value);
    }

    // Combine Method
    public function testCombineSingleValue(): void
    {
        $result = CspValue::combine(CspValue::SELF);

        $this->assertSame("'self'", $result);
    }

    public function testCombineTwoValues(): void
    {
        $result = CspValue::combine(CspValue::SELF, CspValue::DATA);

        $this->assertSame("'self' data:", $result);
    }

    public function testCombineMultipleValues(): void
    {
        $result = CspValue::combine(
            CspValue::SELF,
            CspValue::DATA,
            CspValue::BLOB,
            CspValue::HTTPS
        );

        $this->assertSame("'self' data: blob: https:", $result);
    }

    public function testCombineNoValues(): void
    {
        $result = CspValue::combine();

        $this->assertSame('', $result);
    }

    public function testCombinePreservesOrder(): void
    {
        $result1 = CspValue::combine(CspValue::SELF, CspValue::NONE);
        $result2 = CspValue::combine(CspValue::NONE, CspValue::SELF);

        $this->assertSame("'self' 'none'", $result1);
        $this->assertSame("'none' 'self'", $result2);
        $this->assertNotSame($result1, $result2);
    }

    // Practical Usage Examples
    public function testCombineForImgSrc(): void
    {
        $result = CspValue::combine(CspValue::SELF, CspValue::DATA, CspValue::BLOB);

        $this->assertSame("'self' data: blob:", $result);
    }

    public function testCombineForConnectSrc(): void
    {
        $result = CspValue::combine(CspValue::SELF, CspValue::HTTPS, CspValue::WSS);

        $this->assertSame("'self' https: wss:", $result);
    }

    public function testCombineForWorkerSrc(): void
    {
        $result = CspValue::combine(CspValue::SELF, CspValue::BLOB);

        $this->assertSame("'self' blob:", $result);
    }
}
