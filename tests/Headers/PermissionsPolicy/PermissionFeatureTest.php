<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\PermissionsPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionFeature;

#[CoversClass(PermissionFeature::class)]
final class PermissionFeatureTest extends TestCase
{
    #[Test]
    public function testDirectiveNameReturnsEnumValue(): void
    {
        $feature = PermissionFeature::CAMERA;

        $this->assertSame('camera', $feature->directiveName());
        $this->assertSame($feature->value, $feature->directiveName());
    }

    #[DataProvider('allFeatureCasesProvider')]
    #[Test]
    public function testAllCasesHaveValidDirectiveNames(PermissionFeature $feature, string $expectedValue): void
    {
        $this->assertSame($expectedValue, $feature->value);
        $this->assertSame($expectedValue, $feature->directiveName());
        // RFC compliance: directive names should be lowercase and may contain hyphens
        $this->assertMatchesRegularExpression('/^[a-z][a-z0-9-]*$/', $feature->directiveName());
    }

    /**
     * @return iterable<string, array{feature: PermissionFeature, expectedValue: string}>
     */
    public static function allFeatureCasesProvider(): iterable
    {
        // Sensor APIs
        yield 'ACCELEROMETER' => [
            'feature'       => PermissionFeature::ACCELEROMETER,
            'expectedValue' => 'accelerometer',
        ];
        yield 'AMBIENT_LIGHT_SENSOR' => [
            'feature'       => PermissionFeature::AMBIENT_LIGHT_SENSOR,
            'expectedValue' => 'ambient-light-sensor',
        ];
        yield 'GYROSCOPE' => [
            'feature'       => PermissionFeature::GYROSCOPE,
            'expectedValue' => 'gyroscope',
        ];
        yield 'MAGNETOMETER' => [
            'feature'       => PermissionFeature::MAGNETOMETER,
            'expectedValue' => 'magnetometer',
        ];

        // Media capture
        yield 'CAMERA' => [
            'feature'       => PermissionFeature::CAMERA,
            'expectedValue' => 'camera',
        ];
        yield 'MICROPHONE' => [
            'feature'       => PermissionFeature::MICROPHONE,
            'expectedValue' => 'microphone',
        ];
        yield 'DISPLAY_CAPTURE' => [
            'feature'       => PermissionFeature::DISPLAY_CAPTURE,
            'expectedValue' => 'display-capture',
        ];

        // Geolocation
        yield 'GEOLOCATION' => [
            'feature'       => PermissionFeature::GEOLOCATION,
            'expectedValue' => 'geolocation',
        ];

        // Fullscreen & Picture-in-Picture
        yield 'FULLSCREEN' => [
            'feature'       => PermissionFeature::FULLSCREEN,
            'expectedValue' => 'fullscreen',
        ];
        yield 'PICTURE_IN_PICTURE' => [
            'feature'       => PermissionFeature::PICTURE_IN_PICTURE,
            'expectedValue' => 'picture-in-picture',
        ];

        // Payment & Credentials
        yield 'PAYMENT' => [
            'feature'       => PermissionFeature::PAYMENT,
            'expectedValue' => 'payment',
        ];
        yield 'PUBLICKEY_CREDENTIALS_GET' => [
            'feature'       => PermissionFeature::PUBLICKEY_CREDENTIALS_GET,
            'expectedValue' => 'publickey-credentials-get',
        ];
        yield 'PUBLICKEY_CREDENTIALS_CREATE' => [
            'feature'       => PermissionFeature::PUBLICKEY_CREDENTIALS_CREATE,
            'expectedValue' => 'publickey-credentials-create',
        ];
        yield 'IDENTITY_CREDENTIALS_GET' => [
            'feature'       => PermissionFeature::IDENTITY_CREDENTIALS_GET,
            'expectedValue' => 'identity-credentials-get',
        ];

        // Storage & Clipboard
        yield 'STORAGE_ACCESS' => [
            'feature'       => PermissionFeature::STORAGE_ACCESS,
            'expectedValue' => 'storage-access',
        ];
        yield 'CLIPBOARD_READ' => [
            'feature'       => PermissionFeature::CLIPBOARD_READ,
            'expectedValue' => 'clipboard-read',
        ];
        yield 'CLIPBOARD_WRITE' => [
            'feature'       => PermissionFeature::CLIPBOARD_WRITE,
            'expectedValue' => 'clipboard-write',
        ];

        // User Activation
        yield 'AUTOPLAY' => [
            'feature'       => PermissionFeature::AUTOPLAY,
            'expectedValue' => 'autoplay',
        ];

        // Document
        yield 'DOCUMENT_DOMAIN' => [
            'feature'       => PermissionFeature::DOCUMENT_DOMAIN,
            'expectedValue' => 'document-domain',
        ];
        yield 'ENCRYPTED_MEDIA' => [
            'feature'       => PermissionFeature::ENCRYPTED_MEDIA,
            'expectedValue' => 'encrypted-media',
        ];

        // Navigation & Screen
        yield 'SCREEN_WAKE_LOCK' => [
            'feature'       => PermissionFeature::SCREEN_WAKE_LOCK,
            'expectedValue' => 'screen-wake-lock',
        ];
        yield 'WEB_SHARE' => [
            'feature'       => PermissionFeature::WEB_SHARE,
            'expectedValue' => 'web-share',
        ];

        // Performance
        yield 'SYNC_XHR' => [
            'feature'       => PermissionFeature::SYNC_XHR,
            'expectedValue' => 'sync-xhr',
        ];

        // USB & Serial
        yield 'USB' => [
            'feature'       => PermissionFeature::USB,
            'expectedValue' => 'usb',
        ];
        yield 'SERIAL' => [
            'feature'       => PermissionFeature::SERIAL,
            'expectedValue' => 'serial',
        ];
        yield 'HID' => [
            'feature'       => PermissionFeature::HID,
            'expectedValue' => 'hid',
        ];
        yield 'BLUETOOTH' => [
            'feature'       => PermissionFeature::BLUETOOTH,
            'expectedValue' => 'bluetooth',
        ];

        // VR/XR
        yield 'XR_SPATIAL_TRACKING' => [
            'feature'       => PermissionFeature::XR_SPATIAL_TRACKING,
            'expectedValue' => 'xr-spatial-tracking',
        ];

        // Interest groups
        yield 'BROWSING_TOPICS' => [
            'feature'       => PermissionFeature::BROWSING_TOPICS,
            'expectedValue' => 'browsing-topics',
        ];
        yield 'JOIN_AD_INTEREST_GROUP' => [
            'feature'       => PermissionFeature::JOIN_AD_INTEREST_GROUP,
            'expectedValue' => 'join-ad-interest-group',
        ];
        yield 'RUN_AD_AUCTION' => [
            'feature'       => PermissionFeature::RUN_AD_AUCTION,
            'expectedValue' => 'run-ad-auction',
        ];

        // Attribution
        yield 'ATTRIBUTION_REPORTING' => [
            'feature'       => PermissionFeature::ATTRIBUTION_REPORTING,
            'expectedValue' => 'attribution-reporting',
        ];
    }

    #[Test]
    public function testTotalNumberOfCases(): void
    {
        $cases = PermissionFeature::cases();

        // Verify we have all expected cases (32 as per the enum definition)
        $this->assertCount(32, $cases);
    }

    #[Test]
    public function testCasesAreUnique(): void
    {
        $cases  = PermissionFeature::cases();
        $values = array_map(static fn (PermissionFeature $f): string => $f->value, $cases);

        $this->assertSame($values, array_unique($values));
    }

    #[Test]
    public function testCanCreateFromValue(): void
    {
        $feature = PermissionFeature::from('camera');

        $this->assertSame(PermissionFeature::CAMERA, $feature);
    }

    #[Test]
    public function testTryFromReturnsNullForInvalidValue(): void
    {
        /** @noinspection PhpCaseWithValueNotFoundInEnumInspection Test intentionally uses invalid value */
        $result = PermissionFeature::tryFrom('invalid-feature-name');

        $this->assertNull($result);
    }

    #[Test]
    public function testTryFromReturnsFeatureForValidValue(): void
    {
        $result = PermissionFeature::tryFrom('geolocation');

        $this->assertSame(PermissionFeature::GEOLOCATION, $result);
    }
}
