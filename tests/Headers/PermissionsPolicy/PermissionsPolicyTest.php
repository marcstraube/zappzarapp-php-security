<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\PermissionsPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionDirective;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionFeature;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;

#[CoversClass(PermissionsPolicy::class)]
final class PermissionsPolicyTest extends TestCase
{
    // ========== Constructor Tests ==========

    #[Test]
    public function testConstructorWithEmptyDirectives(): void
    {
        $policy = new PermissionsPolicy();

        $this->assertSame([], $policy->directives());
        $this->assertSame('', $policy->headerValue());
    }

    #[Test]
    public function testConstructorWithDirectives(): void
    {
        $directive = PermissionDirective::blocked(PermissionFeature::CAMERA);
        $policy    = new PermissionsPolicy(['camera' => $directive]);

        $this->assertCount(1, $policy->directives());
        $this->assertSame($directive, $policy->directive(PermissionFeature::CAMERA));
    }

    // ========== withDirective Tests ==========

    #[Test]
    public function testWithDirectiveAddsDirective(): void
    {
        $policy    = new PermissionsPolicy();
        $directive = PermissionDirective::blocked(PermissionFeature::CAMERA);

        $newPolicy = $policy->withDirective($directive);

        $this->assertSame([], $policy->directives());
        $this->assertSame($directive, $newPolicy->directive(PermissionFeature::CAMERA));
        $this->assertNotSame($policy, $newPolicy);
    }

    #[Test]
    public function testWithDirectiveReplacesExisting(): void
    {
        $blocked  = PermissionDirective::blocked(PermissionFeature::CAMERA);
        $selfOnly = PermissionDirective::self(PermissionFeature::CAMERA);

        $policy    = (new PermissionsPolicy())->withDirective($blocked);
        $newPolicy = $policy->withDirective($selfOnly);

        $this->assertSame($blocked, $policy->directive(PermissionFeature::CAMERA));
        $this->assertSame($selfOnly, $newPolicy->directive(PermissionFeature::CAMERA));
    }

    // ========== withBlocked Tests ==========

    #[Test]
    public function testWithBlocked(): void
    {
        $policy    = new PermissionsPolicy();
        $newPolicy = $policy->withBlocked(PermissionFeature::CAMERA);

        $directive = $newPolicy->directive(PermissionFeature::CAMERA);
        $this->assertNotNull($directive);
        $this->assertTrue($directive->isBlocked());
        $this->assertSame('camera=()', $directive->build());
    }

    // ========== withSelf Tests ==========

    #[Test]
    public function testWithSelf(): void
    {
        $policy    = new PermissionsPolicy();
        $newPolicy = $policy->withSelf(PermissionFeature::GEOLOCATION);

        $directive = $newPolicy->directive(PermissionFeature::GEOLOCATION);
        $this->assertNotNull($directive);
        $this->assertFalse($directive->isBlocked());
        $this->assertSame(['self'], $directive->allowlist());
    }

    // ========== withAll Tests ==========

    #[Test]
    public function testWithAll(): void
    {
        $policy    = new PermissionsPolicy();
        $newPolicy = $policy->withAll(PermissionFeature::FULLSCREEN);

        $directive = $newPolicy->directive(PermissionFeature::FULLSCREEN);
        $this->assertNotNull($directive);
        $this->assertTrue($directive->allowsAll());
    }

    // ========== withOrigins Tests ==========

    #[Test]
    public function testWithOrigins(): void
    {
        $origins   = ['https://example.com', 'https://trusted.org'];
        $policy    = new PermissionsPolicy();
        $newPolicy = $policy->withOrigins(PermissionFeature::CAMERA, $origins);

        $directive = $newPolicy->directive(PermissionFeature::CAMERA);
        $this->assertNotNull($directive);
        $this->assertSame($origins, $directive->allowlist());
    }

    #[Test]
    public function testWithOriginsWithEmptyArray(): void
    {
        $policy    = new PermissionsPolicy();
        $newPolicy = $policy->withOrigins(PermissionFeature::CAMERA, []);

        $directive = $newPolicy->directive(PermissionFeature::CAMERA);
        $this->assertNotNull($directive);
        $this->assertTrue($directive->isBlocked());
    }

    // ========== directive() Tests ==========

    #[Test]
    public function testDirectiveReturnsNullForMissingFeature(): void
    {
        $policy = new PermissionsPolicy();

        $this->assertNull($policy->directive(PermissionFeature::CAMERA));
    }

    #[Test]
    public function testDirectiveReturnsExistingDirective(): void
    {
        $directive = PermissionDirective::blocked(PermissionFeature::CAMERA);
        $policy    = (new PermissionsPolicy())->withDirective($directive);

        $this->assertSame($directive, $policy->directive(PermissionFeature::CAMERA));
    }

    // ========== isBlocked() Tests ==========

    #[Test]
    public function testIsBlockedReturnsTrueForBlockedFeature(): void
    {
        $policy = (new PermissionsPolicy())->withBlocked(PermissionFeature::CAMERA);

        $this->assertTrue($policy->isBlocked(PermissionFeature::CAMERA));
    }

    #[Test]
    public function testIsBlockedReturnsFalseForAllowedFeature(): void
    {
        $policy = (new PermissionsPolicy())->withSelf(PermissionFeature::CAMERA);

        $this->assertFalse($policy->isBlocked(PermissionFeature::CAMERA));
    }

    #[Test]
    public function testIsBlockedReturnsFalseForMissingFeature(): void
    {
        $policy = new PermissionsPolicy();

        $this->assertFalse($policy->isBlocked(PermissionFeature::CAMERA));
    }

    // ========== headerValue() Tests ==========

    #[Test]
    public function testHeaderValueEmptyPolicy(): void
    {
        $policy = new PermissionsPolicy();

        $this->assertSame('', $policy->headerValue());
    }

    #[Test]
    public function testHeaderValueSingleDirective(): void
    {
        $policy = (new PermissionsPolicy())->withBlocked(PermissionFeature::CAMERA);

        $this->assertSame('camera=()', $policy->headerValue());
    }

    #[Test]
    public function testHeaderValueMultipleDirectives(): void
    {
        $policy = (new PermissionsPolicy())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withSelf(PermissionFeature::GEOLOCATION);

        $headerValue = $policy->headerValue();

        // Verify both directives are present
        $this->assertStringContainsString('camera=()', $headerValue);
        $this->assertStringContainsString('geolocation=(self)', $headerValue);
        // Verify they are comma-separated
        $this->assertStringContainsString(', ', $headerValue);
    }

    #[Test]
    public function testHeaderValuePreservesDirectiveOrder(): void
    {
        $policy = (new PermissionsPolicy())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withBlocked(PermissionFeature::MICROPHONE)
            ->withBlocked(PermissionFeature::GEOLOCATION);

        $headerValue = $policy->headerValue();
        $directives  = explode(', ', $headerValue);

        $this->assertCount(3, $directives);
        $this->assertSame('camera=()', $directives[0]);
        $this->assertSame('microphone=()', $directives[1]);
        $this->assertSame('geolocation=()', $directives[2]);
    }

    // ========== Static Factory Tests ==========

    #[Test]
    public function testStrictFactory(): void
    {
        $policy = PermissionsPolicy::strict();

        // Verify blocked features
        $this->assertTrue($policy->isBlocked(PermissionFeature::CAMERA));
        $this->assertTrue($policy->isBlocked(PermissionFeature::MICROPHONE));
        $this->assertTrue($policy->isBlocked(PermissionFeature::GEOLOCATION));
        $this->assertTrue($policy->isBlocked(PermissionFeature::PAYMENT));
        $this->assertTrue($policy->isBlocked(PermissionFeature::USB));
        $this->assertTrue($policy->isBlocked(PermissionFeature::BLUETOOTH));
        $this->assertTrue($policy->isBlocked(PermissionFeature::SERIAL));
        $this->assertTrue($policy->isBlocked(PermissionFeature::HID));
        $this->assertTrue($policy->isBlocked(PermissionFeature::DISPLAY_CAPTURE));

        // Verify self-allowed features
        $fullscreen = $policy->directive(PermissionFeature::FULLSCREEN);
        $this->assertNotNull($fullscreen);
        $this->assertSame(['self'], $fullscreen->allowlist());

        $pip = $policy->directive(PermissionFeature::PICTURE_IN_PICTURE);
        $this->assertNotNull($pip);
        $this->assertSame(['self'], $pip->allowlist());
    }

    #[Test]
    public function testStrictFactoryHeaderValue(): void
    {
        $policy      = PermissionsPolicy::strict();
        $headerValue = $policy->headerValue();

        // Verify blocked features are in header
        $this->assertStringContainsString('camera=()', $headerValue);
        $this->assertStringContainsString('microphone=()', $headerValue);
        $this->assertStringContainsString('geolocation=()', $headerValue);

        // Verify self-allowed features
        $this->assertStringContainsString('fullscreen=(self)', $headerValue);
        $this->assertStringContainsString('picture-in-picture=(self)', $headerValue);
    }

    #[Test]
    public function testModerateFactory(): void
    {
        $policy = PermissionsPolicy::moderate();

        // Verify blocked features
        $this->assertTrue($policy->isBlocked(PermissionFeature::CAMERA));
        $this->assertTrue($policy->isBlocked(PermissionFeature::MICROPHONE));
        $this->assertTrue($policy->isBlocked(PermissionFeature::GEOLOCATION));
        $this->assertTrue($policy->isBlocked(PermissionFeature::USB));
        $this->assertTrue($policy->isBlocked(PermissionFeature::BLUETOOTH));
        $this->assertTrue($policy->isBlocked(PermissionFeature::SERIAL));

        // Verify self-allowed features
        $fullscreen = $policy->directive(PermissionFeature::FULLSCREEN);
        $this->assertNotNull($fullscreen);
        $this->assertSame(['self'], $fullscreen->allowlist());

        $autoplay = $policy->directive(PermissionFeature::AUTOPLAY);
        $this->assertNotNull($autoplay);
        $this->assertSame(['self'], $autoplay->allowlist());

        $clipboardWrite = $policy->directive(PermissionFeature::CLIPBOARD_WRITE);
        $this->assertNotNull($clipboardWrite);
        $this->assertSame(['self'], $clipboardWrite->allowlist());
    }

    #[Test]
    public function testEmptyFactory(): void
    {
        $policy = PermissionsPolicy::empty();

        $this->assertSame([], $policy->directives());
        $this->assertSame('', $policy->headerValue());
    }

    // ========== Immutability Tests ==========

    #[Test]
    public function testPolicyIsImmutable(): void
    {
        $original = new PermissionsPolicy();

        $modified = $original->withBlocked(PermissionFeature::CAMERA);

        $this->assertNotSame($original, $modified);
        $this->assertSame([], $original->directives());
        $this->assertCount(1, $modified->directives());
    }

    #[Test]
    public function testChainedModificationsPreserveImmutability(): void
    {
        $step1 = (new PermissionsPolicy())->withBlocked(PermissionFeature::CAMERA);
        $step2 = $step1->withSelf(PermissionFeature::GEOLOCATION);
        $step3 = $step2->withAll(PermissionFeature::FULLSCREEN);

        $this->assertCount(1, $step1->directives());
        $this->assertCount(2, $step2->directives());
        $this->assertCount(3, $step3->directives());
    }

    // ========== Directive Replacement Tests ==========

    #[Test]
    public function testReplacingDirectiveUpdatesPolicy(): void
    {
        $policy = (new PermissionsPolicy())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withSelf(PermissionFeature::CAMERA);

        $directive = $policy->directive(PermissionFeature::CAMERA);
        $this->assertNotNull($directive);
        $this->assertFalse($directive->isBlocked());
        $this->assertSame(['self'], $directive->allowlist());
    }

    // ========== Complex Scenario Tests ==========

    #[Test]
    public function testComplexPolicyConfiguration(): void
    {
        $policy = (new PermissionsPolicy())
            ->withBlocked(PermissionFeature::CAMERA)
            ->withBlocked(PermissionFeature::MICROPHONE)
            ->withSelf(PermissionFeature::FULLSCREEN)
            ->withOrigins(PermissionFeature::GEOLOCATION, ['self', 'https://maps.example.com'])
            ->withAll(PermissionFeature::AUTOPLAY);

        $headerValue = $policy->headerValue();

        $this->assertStringContainsString('camera=()', $headerValue);
        $this->assertStringContainsString('microphone=()', $headerValue);
        $this->assertStringContainsString('fullscreen=(self)', $headerValue);
        $this->assertStringContainsString('geolocation=(self "https://maps.example.com")', $headerValue);
        $this->assertStringContainsString('autoplay=(*)', $headerValue);
    }

    #[DataProvider('directiveCountProvider')]
    #[Test]
    public function testDirectiveCountAfterOperations(int $expectedCount, callable $operations): void
    {
        /** @var PermissionsPolicy $policy */
        $policy = $operations(new PermissionsPolicy());

        $this->assertCount($expectedCount, $policy->directives());
    }

    /**
     * @return iterable<string, array{expectedCount: int, operations: callable}>
     */
    public static function directiveCountProvider(): iterable
    {
        yield 'empty policy' => [
            'expectedCount' => 0,
            'operations'    => static fn (PermissionsPolicy $p): PermissionsPolicy => $p,
        ];

        yield 'single directive' => [
            'expectedCount' => 1,
            'operations'    => static fn (PermissionsPolicy $p): PermissionsPolicy => $p->withBlocked(PermissionFeature::CAMERA),
        ];

        yield 'multiple unique directives' => [
            'expectedCount' => 3,
            'operations'    => static fn (PermissionsPolicy $p): PermissionsPolicy => $p
                ->withBlocked(PermissionFeature::CAMERA)
                ->withBlocked(PermissionFeature::MICROPHONE)
                ->withBlocked(PermissionFeature::GEOLOCATION),
        ];

        yield 'replacing same feature keeps count' => [
            'expectedCount' => 1,
            'operations'    => static fn (PermissionsPolicy $p): PermissionsPolicy => $p
                ->withBlocked(PermissionFeature::CAMERA)
                ->withSelf(PermissionFeature::CAMERA)
                ->withAll(PermissionFeature::CAMERA),
        ];
    }
}
