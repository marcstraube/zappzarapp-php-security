<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

/**
 * Minimal file bodies with the magic bytes libmagic keys on
 */
final class UploadFixtures
{
    public const string PNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89";

    public const string GIF = "GIF89a\x01\x00\x01\x00\x00\x00\x00;";

    public const string JPEG = "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9";

    public const string PDF = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";

    /**
     * "hello world" deflated, with the mtime field zeroed so the bytes are
     * fixed. Written out rather than produced with gzencode() to keep the
     * test suite off ext-zlib.
     */
    public const string GZIP = "\x1F\x8B\x08\x00\x00\x00\x00\x00\x02\x03\xCBH\xCD\xC9\xC9W(\xCF/\xCAI\x01\x00\x85\x11J\x0D\x0B\x00\x00\x00";

    public const string TEXT = "hello world\n";

    public const string PHP = '<?php echo 1;';
}
