<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

/**
 * URI schemes enum
 */
enum UriScheme: string
{
    case HTTP       = 'http';
    case HTTPS      = 'https';
    case FTP        = 'ftp';
    case FTPS       = 'ftps';
    case MAILTO     = 'mailto';
    case TEL        = 'tel';
    case SMS        = 'sms';
    case DATA       = 'data';
    case JAVASCRIPT = 'javascript';
    case VBSCRIPT   = 'vbscript';
    case FILE       = 'file';

    /**
     * Check if this scheme is dangerous for XSS
     */
    public function isDangerous(): bool
    {
        return match ($this) {
            self::JAVASCRIPT, self::VBSCRIPT, self::DATA => true,
            default => false,
        };
    }

    /**
     * Check if this scheme is safe for web
     */
    public function isSafeForWeb(): bool
    {
        return match ($this) {
            self::HTTP, self::HTTPS, self::MAILTO, self::TEL => true,
            default => false,
        };
    }
}
