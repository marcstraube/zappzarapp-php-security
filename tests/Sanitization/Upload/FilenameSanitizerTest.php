<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw InvalidFilenameException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;
use Zappzarapp\Security\Sanitization\Upload\FilenameSanitizer;

#[CoversClass(FilenameSanitizer::class)]
final class FilenameSanitizerTest extends TestCase
{
    private FilenameSanitizer $sanitizer;

    protected function setUp(): void
    {
        $this->sanitizer = new FilenameSanitizer();
    }

    // --- Accepted names ---

    /**
     * @return array<string, array{string, string}>
     */
    public static function safeNameProvider(): array
    {
        return [
            'plain name'           => ['photo.jpg', 'photo.jpg'],
            'uppercase preserved'  => ['Photo.JPG', 'Photo.JPG'],
            'digits and dashes'    => ['report-2024_v2.pdf', 'report-2024_v2.pdf'],
            'no extension'         => ['README', 'README'],
            'multiple dots'        => ['archive.tar.gz', 'archive.tar.gz'],
            'single character'     => ['a', 'a'],
        ];
    }

    #[DataProvider('safeNameProvider')]
    #[Test]
    public function testSanitizeKeepsSafeNames(string $input, string $expected): void
    {
        $this->assertSame($expected, $this->sanitizer->sanitize($input));
    }

    // --- Directory components ---

    /**
     * @return array<string, array{string, string}>
     */
    public static function directoryComponentProvider(): array
    {
        return [
            'relative traversal'   => ['../../etc/passwd', 'passwd'],
            'absolute path'        => ['/var/www/html/index.html', 'index.html'],
            'nested path'          => ['a/b/c.png', 'c.png'],
            'windows path'         => ['C:\\Users\\bob\\evil.php', 'evil.php'],
            'windows traversal'    => ['..\\..\\windows\\win.ini', 'win.ini'],
            'mixed separators'     => ['a/b\\c/d.txt', 'd.txt'],
        ];
    }

    #[DataProvider('directoryComponentProvider')]
    #[Test]
    public function testSanitizeStripsDirectoryComponents(string $input, string $expected): void
    {
        $this->assertSame($expected, $this->sanitizer->sanitize($input));
    }

    #[Test]
    public function testSanitizeNeverReturnsASeparator(): void
    {
        $result = $this->sanitizer->sanitize('a/b\\c.txt');

        $this->assertStringNotContainsString('/', $result);
        $this->assertStringNotContainsString('\\', $result);
    }

    // --- Hostile characters ---

    #[Test]
    public function testSanitizeRejectsNullByte(): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('NUL byte');

        $this->sanitizer->sanitize("shell.php\0.jpg");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controlCharacterProvider(): array
    {
        return [
            'line feed'       => ["report\n.pdf"],
            'carriage return' => ["report\r.pdf"],
            'tab'             => ["report\t.pdf"],
            'unit separator'  => ["report\x1F.pdf"],
            'delete'          => ["report\x7F.pdf"],
        ];
    }

    #[DataProvider('controlCharacterProvider')]
    #[Test]
    public function testSanitizeRejectsControlCharacters(string $filename): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('control characters');

        $this->sanitizer->sanitize($filename);
    }

    #[Test]
    public function testSanitizeRejectsInvalidUtf8(): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('not valid UTF-8');

        $this->sanitizer->sanitize("photo\xFF\xFE.jpg");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsafeUnicodeProvider(): array
    {
        return [
            'right-to-left override' => ["photo\u{202E}gpj.exe"],
            'left-to-right mark'     => ["photo\u{200E}.jpg"],
            'zero width space'       => ["photo\u{200B}.jpg"],
            'isolate'                => ["photo\u{2066}.jpg"],
            'byte order mark'        => ["\u{FEFF}photo.jpg"],
        ];
    }

    #[DataProvider('unsafeUnicodeProvider')]
    #[Test]
    public function testSanitizeRejectsBidirectionalAndZeroWidthCharacters(string $filename): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('bidirectional or zero-width');

        $this->sanitizer->sanitize($filename);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function traversalProvider(): array
    {
        return [
            'parent directory'  => ['..'],
            'current directory' => ['.'],
        ];
    }

    #[DataProvider('traversalProvider')]
    #[Test]
    public function testSanitizeRejectsTraversalSequences(string $filename): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('directory traversal sequence');

        $this->sanitizer->sanitize($filename);
    }

    // --- Dots and spaces ---

    /**
     * @return array<string, array{string, string}>
     */
    public static function trimmedNameProvider(): array
    {
        return [
            'trailing dot'          => ['evil.php.', 'evil.php'],
            'trailing dots'         => ['evil.php...', 'evil.php'],
            'trailing space'        => ['report.pdf ', 'report.pdf'],
            'trailing dot at space' => ['report.pdf . ', 'report.pdf'],
            'leading dot'           => ['.htaccess', 'htaccess'],
            'leading dots'          => ['...bashrc', 'bashrc'],
        ];
    }

    #[DataProvider('trimmedNameProvider')]
    #[Test]
    public function testSanitizeTrimsLeadingAndTrailingDots(string $input, string $expected): void
    {
        $this->assertSame($expected, $this->sanitizer->sanitize($input));
    }

    #[Test]
    public function testSanitizeRejectsNameWithoutUsableCharacters(): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('no usable characters');

        $this->sanitizer->sanitize('...');
    }

    // --- Character replacement ---

    /**
     * @return array<string, array{string, string}>
     */
    public static function replacedCharacterProvider(): array
    {
        return [
            'spaces and brackets' => ['My Report (1).pdf', 'My_Report__1_.pdf'],
            'semicolon'           => ['a;b.txt', 'a_b.txt'],
            'ampersand'           => ['a&b.txt', 'a_b.txt'],
            'quote'               => ['a"b.txt', 'a_b.txt'],
            'colon'               => ['a:b.txt', 'a_b.txt'],
            'non ascii'           => ["\u{00C4}rger.txt", '__rger.txt'],
        ];
    }

    #[DataProvider('replacedCharacterProvider')]
    #[Test]
    public function testSanitizeReplacesUnsafeCharacters(string $input, string $expected): void
    {
        $this->assertSame($expected, $this->sanitizer->sanitize($input));
    }

    // --- Reserved device names ---

    /**
     * @return array<string, array{string}>
     */
    public static function reservedNameProvider(): array
    {
        return [
            'CON'           => ['CON'],
            'lowercase con' => ['con.txt'],
            'PRN'           => ['PRN.pdf'],
            'AUX'           => ['aux.png'],
            'NUL'           => ['NUL.jpg'],
            'COM1'          => ['COM1.txt'],
            'COM9'          => ['com9.txt'],
            'LPT1'          => ['LPT1.txt'],
            'LPT9'          => ['lpt9.txt'],
        ];
    }

    #[DataProvider('reservedNameProvider')]
    #[Test]
    public function testSanitizeRejectsReservedDeviceNames(string $filename): void
    {
        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('reserved device name');

        $this->sanitizer->sanitize($filename);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonReservedNameProvider(): array
    {
        return [
            'COM0 is not a device' => ['COM0.txt'],
            'longer word'          => ['CONSOLE.txt'],
            'suffix only'          => ['my-con.txt'],
            'device as extension'  => ['report.con'],
        ];
    }

    #[DataProvider('nonReservedNameProvider')]
    #[Test]
    public function testSanitizeKeepsNamesThatOnlyLookReserved(string $filename): void
    {
        $this->assertSame($filename, $this->sanitizer->sanitize($filename));
    }

    // --- Length ---

    #[Test]
    public function testSanitizeAcceptsNameAtTheLengthLimit(): void
    {
        $sanitizer = new FilenameSanitizer(10);

        $this->assertSame('abcdef.txt', $sanitizer->sanitize('abcdef.txt'));
    }

    #[Test]
    public function testSanitizeRejectsNameAboveTheLengthLimit(): void
    {
        $sanitizer = new FilenameSanitizer(10);

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('Filename is 11 bytes long, the maximum is 10');

        $sanitizer->sanitize('abcdefg.txt');
    }

    #[Test]
    public function testSanitizeAcceptsTwoHundredFiftyFiveBytesByDefault(): void
    {
        $this->assertSame(255, FilenameSanitizer::DEFAULT_MAX_LENGTH);

        $name = str_repeat('a', 251) . '.txt';

        $this->assertSame(255, strlen($name));
        $this->assertSame($name, $this->sanitizer->sanitize($name));
    }

    #[Test]
    public function testSanitizeRejectsTwoHundredFiftySixBytesByDefault(): void
    {
        $name = str_repeat('a', 252) . '.txt';

        $this->assertSame(256, strlen($name));

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('Filename is 256 bytes long, the maximum is 255');

        $this->sanitizer->sanitize($name);
    }

    // --- Unicode opt-in ---

    #[Test]
    public function testUnicodeModeKeepsLetters(): void
    {
        $sanitizer = new FilenameSanitizer(allowUnicode: true);

        $this->assertSame("\u{00C4}rger.txt", $sanitizer->sanitize("\u{00C4}rger.txt"));
    }

    #[Test]
    public function testUnicodeModeStillReplacesPunctuation(): void
    {
        $sanitizer = new FilenameSanitizer(allowUnicode: true);

        $this->assertSame('a_b.txt', $sanitizer->sanitize('a b.txt'));
    }

    #[Test]
    public function testUnicodeModeNormalizesToNfc(): void
    {
        $sanitizer = new FilenameSanitizer(allowUnicode: true);

        // "A" followed by a combining diaeresis must collapse to the
        // single precomposed code point, so two spellings of the same
        // visible name cannot coexist
        $decomposed = "A\u{0308}rger.txt";
        $composed   = "\u{00C4}rger.txt";

        $this->assertNotSame($composed, $decomposed);
        $this->assertSame($composed, $sanitizer->sanitize($decomposed));
    }

    #[Test]
    public function testUnicodeModeStillStripsDirectoryComponents(): void
    {
        $sanitizer = new FilenameSanitizer(allowUnicode: true);

        $this->assertSame('passwd', $sanitizer->sanitize('../../etc/passwd'));
    }
}
