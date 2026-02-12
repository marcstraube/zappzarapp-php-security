<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\PermissionsPolicy;

/**
 * Permissions-Policy feature names
 *
 * Standardized feature names for the Permissions-Policy header.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
 * @see https://www.w3.org/TR/permissions-policy/
 */
enum PermissionFeature: string
{
    // Sensor APIs
    case ACCELEROMETER        = 'accelerometer';
    case AMBIENT_LIGHT_SENSOR = 'ambient-light-sensor';
    case GYROSCOPE            = 'gyroscope';
    case MAGNETOMETER         = 'magnetometer';

    // Media capture
    case CAMERA          = 'camera';
    case MICROPHONE      = 'microphone';
    case DISPLAY_CAPTURE = 'display-capture';

    // Geolocation
    case GEOLOCATION = 'geolocation';

    // Fullscreen & Picture-in-Picture
    case FULLSCREEN         = 'fullscreen';
    case PICTURE_IN_PICTURE = 'picture-in-picture';

    // Payment & Credentials
    case PAYMENT                      = 'payment';
    case PUBLICKEY_CREDENTIALS_GET    = 'publickey-credentials-get';
    case PUBLICKEY_CREDENTIALS_CREATE = 'publickey-credentials-create';
    case IDENTITY_CREDENTIALS_GET     = 'identity-credentials-get';

    // Storage & Clipboard
    case STORAGE_ACCESS  = 'storage-access';
    case CLIPBOARD_READ  = 'clipboard-read';
    case CLIPBOARD_WRITE = 'clipboard-write';

    // User Activation
    case AUTOPLAY = 'autoplay';

    // Document
    case DOCUMENT_DOMAIN = 'document-domain';
    case ENCRYPTED_MEDIA = 'encrypted-media';

    // Navigation & Screen
    case SCREEN_WAKE_LOCK = 'screen-wake-lock';
    case WEB_SHARE        = 'web-share';

    // Performance
    case SYNC_XHR = 'sync-xhr';

    // USB & Serial
    case USB       = 'usb';
    case SERIAL    = 'serial';
    case HID       = 'hid';
    case BLUETOOTH = 'bluetooth';

    // VR/XR
    case XR_SPATIAL_TRACKING = 'xr-spatial-tracking';

    // Interest groups
    case BROWSING_TOPICS        = 'browsing-topics';
    case JOIN_AD_INTEREST_GROUP = 'join-ad-interest-group';
    case RUN_AD_AUCTION         = 'run-ad-auction';

    // Attribution
    case ATTRIBUTION_REPORTING = 'attribution-reporting';

    /**
     * Get the header directive name
     */
    public function directiveName(): string
    {
        return $this->value;
    }
}
