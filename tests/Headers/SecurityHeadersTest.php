<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Headers\Coep\CoepValue;
use Zappzarapp\Security\Headers\Coop\CoopValue;
use Zappzarapp\Security\Headers\Corp\CorpValue;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

#[CoversClass(SecurityHeaders::class)]
final class SecurityHeadersTest extends TestCase
{
    #[Test]
    public function testDefaultValues(): void
    {
        $headers = new SecurityHeaders();

        $this->assertNull($headers->hsts);
        $this->assertNull($headers->coop);
        $this->assertNull($headers->coep);
        $this->assertNull($headers->corp);
        $this->assertNull($headers->referrerPolicy);
        $this->assertNull($headers->xFrameOptions);
        $this->assertNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
        $this->assertNull($headers->csp);
    }

    #[Test]
    public function testWithHsts(): void
    {
        $headers = new SecurityHeaders();
        $hsts    = HstsConfig::strict();

        $newHeaders = $headers->withHsts($hsts);

        $this->assertNull($headers->hsts);
        $this->assertSame($hsts, $newHeaders->hsts);
        $this->assertNotSame($headers, $newHeaders);
    }

    #[Test]
    public function testWithoutHsts(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutHsts();

        $this->assertNotNull($headers->hsts);
        $this->assertNull($newHeaders->hsts);
    }

    #[Test]
    public function testWithCoop(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withCoop(CoopValue::SAME_ORIGIN);

        $this->assertNull($headers->coop);
        $this->assertSame(CoopValue::SAME_ORIGIN, $newHeaders->coop);
    }

    #[Test]
    public function testWithoutCoop(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutCoop();

        $this->assertNotNull($headers->coop);
        $this->assertNull($newHeaders->coop);
    }

    #[Test]
    public function testWithCoep(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withCoep(CoepValue::REQUIRE_CORP);

        $this->assertNull($headers->coep);
        $this->assertSame(CoepValue::REQUIRE_CORP, $newHeaders->coep);
    }

    #[Test]
    public function testWithoutCoep(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutCoep();

        $this->assertNotNull($headers->coep);
        $this->assertNull($newHeaders->coep);
    }

    #[Test]
    public function testWithCorp(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withCorp(CorpValue::SAME_ORIGIN);

        $this->assertNull($headers->corp);
        $this->assertSame(CorpValue::SAME_ORIGIN, $newHeaders->corp);
    }

    #[Test]
    public function testWithoutCorp(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutCorp();

        $this->assertNotNull($headers->corp);
        $this->assertNull($newHeaders->corp);
    }

    #[Test]
    public function testWithReferrerPolicy(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withReferrerPolicy(ReferrerPolicyValue::NO_REFERRER);

        $this->assertNull($headers->referrerPolicy);
        $this->assertSame(ReferrerPolicyValue::NO_REFERRER, $newHeaders->referrerPolicy);
    }

    #[Test]
    public function testWithoutReferrerPolicy(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutReferrerPolicy();

        $this->assertNotNull($headers->referrerPolicy);
        $this->assertNull($newHeaders->referrerPolicy);
    }

    #[Test]
    public function testWithXFrameOptions(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withXFrameOptions(XFrameOptionsValue::DENY);

        $this->assertNull($headers->xFrameOptions);
        $this->assertSame(XFrameOptionsValue::DENY, $newHeaders->xFrameOptions);
    }

    #[Test]
    public function testWithoutXFrameOptions(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutXFrameOptions();

        $this->assertNotNull($headers->xFrameOptions);
        $this->assertNull($newHeaders->xFrameOptions);
    }

    #[Test]
    public function testWithXContentTypeOptions(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withoutXContentTypeOptions();

        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertFalse($newHeaders->xContentTypeOptions);
    }

    #[Test]
    public function testWithXXssProtection(): void
    {
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withoutXXssProtection();

        $this->assertTrue($headers->xXssProtection);
        $this->assertFalse($newHeaders->xXssProtection);
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $headers = SecurityHeaders::strict();

        $this->assertNotNull($headers->hsts);
        $this->assertSame(HstsConfig::RECOMMENDED_MAX_AGE, $headers->hsts->maxAge);
        $this->assertTrue($headers->hsts->includeSubDomains);
        $this->assertSame(CoopValue::SAME_ORIGIN, $headers->coop);
        $this->assertSame(CoepValue::REQUIRE_CORP, $headers->coep);
        $this->assertSame(CorpValue::SAME_ORIGIN, $headers->corp);
        $this->assertSame(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN, $headers->referrerPolicy);
        $this->assertSame(XFrameOptionsValue::DENY, $headers->xFrameOptions);
        $this->assertNotNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertFalse($headers->xXssProtection);
    }

    #[Test]
    public function testModerateFactory(): void
    {
        $headers = SecurityHeaders::moderate();

        $this->assertNotNull($headers->hsts);
        $this->assertSame(31536000, $headers->hsts->maxAge);
        $this->assertFalse($headers->hsts->includeSubDomains);
        $this->assertNull($headers->coop);
        $this->assertNull($headers->coep);
        $this->assertNull($headers->corp);
        $this->assertSame(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN, $headers->referrerPolicy);
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $headers->xFrameOptions);
        $this->assertNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
    }

    #[Test]
    public function testLegacyFactory(): void
    {
        $headers = SecurityHeaders::legacy();

        $this->assertNotNull($headers->hsts);
        $this->assertNull($headers->coop);
        $this->assertNull($headers->coep);
        $this->assertNull($headers->corp);
        $this->assertSame(ReferrerPolicyValue::NO_REFERRER_WHEN_DOWNGRADE, $headers->referrerPolicy);
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $headers->xFrameOptions);
        $this->assertNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
    }

    #[Test]
    public function testDevelopmentFactory(): void
    {
        $headers = SecurityHeaders::development();

        $this->assertNull($headers->hsts);
        $this->assertNull($headers->coop);
        $this->assertNull($headers->coep);
        $this->assertNull($headers->corp);
        $this->assertNull($headers->referrerPolicy);
        $this->assertNull($headers->xFrameOptions);
        $this->assertNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
    }

    #[Test]
    public function testImmutability(): void
    {
        $original = new SecurityHeaders();

        $original->withHsts(HstsConfig::strict());
        $original->withCoop(CoopValue::SAME_ORIGIN);
        $original->withCoep(CoepValue::REQUIRE_CORP);
        $original->withoutXContentTypeOptions();

        $this->assertNull($original->hsts);
        $this->assertNull($original->coop);
        $this->assertNull($original->coep);
        $this->assertTrue($original->xContentTypeOptions);
    }

    #[Test]
    public function testChainedModifications(): void
    {
        $headers = (new SecurityHeaders())
            ->withHsts(HstsConfig::strict())
            ->withCoop(CoopValue::SAME_ORIGIN)
            ->withCoep(CoepValue::REQUIRE_CORP)
            ->withCorp(CorpValue::SAME_ORIGIN)
            ->withReferrerPolicy(ReferrerPolicyValue::NO_REFERRER)
            ->withXFrameOptions(XFrameOptionsValue::DENY)
            ->withXContentTypeOptions()
            ->withXXssProtection();

        $this->assertNotNull($headers->hsts);
        $this->assertSame(CoopValue::SAME_ORIGIN, $headers->coop);
        $this->assertSame(CoepValue::REQUIRE_CORP, $headers->coep);
        $this->assertSame(CorpValue::SAME_ORIGIN, $headers->corp);
        $this->assertSame(ReferrerPolicyValue::NO_REFERRER, $headers->referrerPolicy);
        $this->assertSame(XFrameOptionsValue::DENY, $headers->xFrameOptions);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
    }

    #[Test]
    public function testReplaceHstsWithDifferentValue(): void
    {
        $oldHsts = HstsConfig::testing();
        $newHsts = HstsConfig::strict();

        $headers    = (new SecurityHeaders())->withHsts($oldHsts);
        $newHeaders = $headers->withHsts($newHsts);

        $this->assertSame($newHsts, $newHeaders->hsts);
        $this->assertNotSame($oldHsts, $newHeaders->hsts);
    }

    #[Test]
    public function testReplaceCoopWithDifferentValue(): void
    {
        $headers    = SecurityHeaders::strict()->withCoop(CoopValue::SAME_ORIGIN_ALLOW_POPUPS);
        $newHeaders = $headers->withCoop(CoopValue::UNSAFE_NONE);

        $this->assertSame(CoopValue::UNSAFE_NONE, $newHeaders->coop);
    }

    #[Test]
    public function testReplaceCoepWithDifferentValue(): void
    {
        // Start with strict which has REQUIRE_CORP, change to CREDENTIALLESS, then back
        $headers    = SecurityHeaders::strict();
        $step1      = $headers->withCoep(CoepValue::CREDENTIALLESS);
        $step2      = $step1->withCoep(CoepValue::REQUIRE_CORP);

        // Verify each step gets the new value, not the old
        $this->assertSame(CoepValue::CREDENTIALLESS, $step1->coep);
        $this->assertSame(CoepValue::REQUIRE_CORP, $step2->coep);
    }

    #[Test]
    public function testReplaceCorpWithDifferentValue(): void
    {
        $headers    = SecurityHeaders::strict()->withCorp(CorpValue::SAME_SITE);
        $newHeaders = $headers->withCorp(CorpValue::CROSS_ORIGIN);

        $this->assertSame(CorpValue::CROSS_ORIGIN, $newHeaders->corp);
    }

    #[Test]
    public function testReplaceReferrerPolicyWithDifferentValue(): void
    {
        $headers    = SecurityHeaders::strict()->withReferrerPolicy(ReferrerPolicyValue::NO_REFERRER);
        $newHeaders = $headers->withReferrerPolicy(ReferrerPolicyValue::SAME_ORIGIN);

        $this->assertSame(ReferrerPolicyValue::SAME_ORIGIN, $newHeaders->referrerPolicy);
    }

    #[Test]
    public function testReplaceXFrameOptionsWithDifferentValue(): void
    {
        // Start with DENY (from strict), change to SAMEORIGIN, then back to DENY
        $headers = SecurityHeaders::strict();
        $step1   = $headers->withXFrameOptions(XFrameOptionsValue::SAMEORIGIN);
        $step2   = $step1->withXFrameOptions(XFrameOptionsValue::DENY);

        // Verify each step gets the new value, not the old
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $step1->xFrameOptions);
        $this->assertSame(XFrameOptionsValue::DENY, $step2->xFrameOptions);
    }

    #[Test]
    public function testReplacePermissionsPolicyWithDifferentValue(): void
    {
        $oldPolicy  = PermissionsPolicy::moderate();
        $newPolicy  = PermissionsPolicy::strict();
        $headers    = SecurityHeaders::strict()->withPermissionsPolicy($oldPolicy);
        $newHeaders = $headers->withPermissionsPolicy($newPolicy);

        $this->assertSame($newPolicy, $newHeaders->permissionsPolicy);
    }

    #[Test]
    public function testReplaceCspWithDifferentValue(): void
    {
        $oldCsp = CspDirectives::strict();
        $newCsp = CspDirectives::legacy();

        $headers = (new SecurityHeaders())->withCsp($oldCsp);
        $result  = $headers->withCsp($newCsp);

        // Verify the new CSP is returned, not the old one
        $this->assertSame($newCsp, $result->csp);
        $this->assertNotSame($oldCsp, $result->csp);
    }

    #[Test]
    public function testWithoutCspWhenCspWasSet(): void
    {
        $csp     = CspDirectives::strict();
        $headers = (new SecurityHeaders())->withCsp($csp);
        $result  = $headers->withoutCsp();

        // CSP should be null, not the old value
        $this->assertNull($result->csp);
    }

    #[Test]
    public function testWithPermissionsPolicy(): void
    {
        $policy     = PermissionsPolicy::strict();
        $headers    = new SecurityHeaders();
        $newHeaders = $headers->withPermissionsPolicy($policy);

        $this->assertNull($headers->permissionsPolicy);
        $this->assertSame($policy, $newHeaders->permissionsPolicy);
        $this->assertNotSame($headers, $newHeaders);
    }

    #[Test]
    public function testWithoutPermissionsPolicy(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutPermissionsPolicy();

        $this->assertNotNull($headers->permissionsPolicy);
        $this->assertNull($newHeaders->permissionsPolicy);
    }

    #[Test]
    public function testWithoutPermissionsPolicyPreservesOtherHeaders(): void
    {
        $headers    = SecurityHeaders::strict();
        $newHeaders = $headers->withoutPermissionsPolicy();

        // Verify other headers are preserved
        $this->assertNotNull($newHeaders->hsts);
        $this->assertSame(CoopValue::SAME_ORIGIN, $newHeaders->coop);
        $this->assertSame(CoepValue::REQUIRE_CORP, $newHeaders->coep);
        $this->assertSame(CorpValue::SAME_ORIGIN, $newHeaders->corp);
        $this->assertSame(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN, $newHeaders->referrerPolicy);
        $this->assertSame(XFrameOptionsValue::DENY, $newHeaders->xFrameOptions);
        $this->assertTrue($newHeaders->xContentTypeOptions);
        $this->assertFalse($newHeaders->xXssProtection);
    }

    #[Test]
    public function testApiFactory(): void
    {
        $headers = SecurityHeaders::api();

        $this->assertNotNull($headers->hsts);
        $this->assertSame(HstsConfig::RECOMMENDED_MAX_AGE, $headers->hsts->maxAge);
        $this->assertTrue($headers->hsts->includeSubDomains);
        $this->assertNull($headers->coop);
        $this->assertNull($headers->coep);
        $this->assertSame(CorpValue::SAME_ORIGIN, $headers->corp);
        $this->assertNull($headers->referrerPolicy);
        $this->assertNull($headers->xFrameOptions);
        $this->assertNull($headers->permissionsPolicy);
        $this->assertTrue($headers->xContentTypeOptions);
        $this->assertTrue($headers->xXssProtection);
    }

    #[Test]
    public function testStrictPresetIsImmutable(): void
    {
        $strict = SecurityHeaders::strict();

        // Modifying returns new instance
        $modified = $strict->withoutHsts();

        // Original unchanged
        $this->assertNotNull($strict->hsts);
        $this->assertNull($modified->hsts);
        $this->assertNotSame($strict, $modified);
    }

    #[Test]
    public function testModeratePresetIsImmutable(): void
    {
        $moderate = SecurityHeaders::moderate();

        // Modifying returns new instance
        $modified = $moderate->withXFrameOptions(XFrameOptionsValue::DENY);

        // Original unchanged
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $moderate->xFrameOptions);
        $this->assertSame(XFrameOptionsValue::DENY, $modified->xFrameOptions);
        $this->assertNotSame($moderate, $modified);
    }

    #[Test]
    public function testApiPresetIsImmutable(): void
    {
        $api = SecurityHeaders::api();

        // Modifying returns new instance
        $modified = $api->withCoop(CoopValue::SAME_ORIGIN);

        // Original unchanged
        $this->assertNull($api->coop);
        $this->assertSame(CoopValue::SAME_ORIGIN, $modified->coop);
        $this->assertNotSame($api, $modified);
    }

    #[Test]
    public function testBuilderCanCustomizeStrictPreset(): void
    {
        $customized = SecurityHeaders::strict()
            ->withoutCoep()
            ->withoutCoop()
            ->withXFrameOptions(XFrameOptionsValue::SAMEORIGIN);

        // Modified headers
        $this->assertNull($customized->coep);
        $this->assertNull($customized->coop);
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $customized->xFrameOptions);

        // Unchanged headers
        $this->assertNotNull($customized->hsts);
        $this->assertSame(CorpValue::SAME_ORIGIN, $customized->corp);
        $this->assertSame(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN, $customized->referrerPolicy);
        $this->assertTrue($customized->xContentTypeOptions);
    }

    #[Test]
    public function testBuilderCanCustomizeModeratePreset(): void
    {
        $customized = SecurityHeaders::moderate()
            ->withCoop(CoopValue::SAME_ORIGIN)
            ->withCoep(CoepValue::REQUIRE_CORP);

        // Added headers
        $this->assertSame(CoopValue::SAME_ORIGIN, $customized->coop);
        $this->assertSame(CoepValue::REQUIRE_CORP, $customized->coep);

        // Unchanged headers from moderate
        $this->assertNotNull($customized->hsts);
        $this->assertSame(31536000, $customized->hsts->maxAge);
        $this->assertSame(XFrameOptionsValue::SAMEORIGIN, $customized->xFrameOptions);
        $this->assertSame(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN, $customized->referrerPolicy);
    }

    #[Test]
    public function testBuilderCanCustomizeApiPreset(): void
    {
        $customized = SecurityHeaders::api()
            ->withReferrerPolicy(ReferrerPolicyValue::NO_REFERRER)
            ->withCorp(CorpValue::CROSS_ORIGIN);

        // Modified/added headers
        $this->assertSame(ReferrerPolicyValue::NO_REFERRER, $customized->referrerPolicy);
        $this->assertSame(CorpValue::CROSS_ORIGIN, $customized->corp);

        // Unchanged headers from api
        $this->assertNotNull($customized->hsts);
        $this->assertNull($customized->xFrameOptions);
        $this->assertTrue($customized->xContentTypeOptions);
    }
}
