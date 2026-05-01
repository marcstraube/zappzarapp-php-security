<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

final class ResourceDirectivesTest extends TestCase
{
    #[Test]
    public function testDefaultValues(): void
    {
        $resources = new ResourceDirectives();

        $this->assertSame("'self' data:", $resources->img);
        $this->assertSame("'self'", $resources->font);
        $this->assertSame("'self'", $resources->connect);
        $this->assertSame("'self'", $resources->media);
        $this->assertSame("'self'", $resources->worker);
        $this->assertSame("'self'", $resources->child);
        $this->assertSame("'self'", $resources->frame);
        $this->assertSame("'self'", $resources->manifest);
    }

    #[Test]
    public function testCustomValues(): void
    {
        $resources = new ResourceDirectives(
            img: "'self' https://images.example.com",
            font: "'self' https://fonts.example.com",
            connect: "'self' https://api.example.com"
        );

        $this->assertSame("'self' https://images.example.com", $resources->img);
        $this->assertSame("'self' https://fonts.example.com", $resources->font);
        $this->assertSame("'self' https://api.example.com", $resources->connect);
    }

    #[Test]
    public function testWithImgReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withImg("'self' https://cdn.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self' data:", $original->img);
        $this->assertSame("'self' https://cdn.example.com", $modified->img);
    }

    #[Test]
    public function testWithFontReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withFont("'self' https://fonts.gstatic.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->font);
        $this->assertSame("'self' https://fonts.gstatic.com", $modified->font);
    }

    #[Test]
    public function testWithConnectReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withConnect("'self' wss://api.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->connect);
        $this->assertSame("'self' wss://api.example.com", $modified->connect);
    }

    #[Test]
    public function testFluentApiChaining(): void
    {
        $resources = (new ResourceDirectives())
            ->withImg("'self' https://images.example.com")
            ->withFont("'self' https://fonts.example.com")
            ->withConnect("'self' https://api.example.com");

        $this->assertSame("'self' https://images.example.com", $resources->img);
        $this->assertSame("'self' https://fonts.example.com", $resources->font);
        $this->assertSame("'self' https://api.example.com", $resources->connect);
    }

    // New Directives Tests
    #[Test]
    public function testWithMediaReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withMedia("'self' https://media.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->media);
        $this->assertSame("'self' https://media.example.com", $modified->media);
    }

    #[Test]
    public function testWithWorkerReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withWorker("'self' blob:");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->worker);
        $this->assertSame("'self' blob:", $modified->worker);
    }

    #[Test]
    public function testWithChildReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withChild("'self' https://iframe.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->child);
        $this->assertSame("'self' https://iframe.example.com", $modified->child);
    }

    #[Test]
    public function testWithFrameReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withFrame("'self' https://embed.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->frame);
        $this->assertSame("'self' https://embed.example.com", $modified->frame);
    }

    #[Test]
    public function testWithManifestReturnsNewInstance(): void
    {
        $original = new ResourceDirectives();
        $modified = $original->withManifest("'self' https://pwa.example.com");

        $this->assertNotSame($original, $modified);
        $this->assertSame("'self'", $original->manifest);
        $this->assertSame("'self' https://pwa.example.com", $modified->manifest);
    }

    #[Test]
    public function testExtendedFluentApiChaining(): void
    {
        $resources = (new ResourceDirectives())
            ->withImg("'self' https://images.example.com")
            ->withFont("'self' https://fonts.example.com")
            ->withConnect("'self' https://api.example.com")
            ->withMedia("'self' https://media.example.com")
            ->withWorker("'self' blob:")
            ->withChild("'self' https://iframe.example.com")
            ->withFrame("'self' https://embed.example.com")
            ->withManifest("'self' https://pwa.example.com");

        $this->assertSame("'self' https://images.example.com", $resources->img);
        $this->assertSame("'self' https://fonts.example.com", $resources->font);
        $this->assertSame("'self' https://api.example.com", $resources->connect);
        $this->assertSame("'self' https://media.example.com", $resources->media);
        $this->assertSame("'self' blob:", $resources->worker);
        $this->assertSame("'self' https://iframe.example.com", $resources->child);
        $this->assertSame("'self' https://embed.example.com", $resources->frame);
        $this->assertSame("'self' https://pwa.example.com", $resources->manifest);
    }

    // Validation Tests
    #[Test]
    public function testValidationThrowsForSemicolonInImg(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('img-src');

        new ResourceDirectives(img: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForNewlineInFont(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('font-src');

        new ResourceDirectives(font: "'self'\nevil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInConnect(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('connect-src');

        new ResourceDirectives(connect: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInMedia(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('media-src');

        new ResourceDirectives(media: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInWorker(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('worker-src');

        new ResourceDirectives(worker: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInChild(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('child-src');

        new ResourceDirectives(child: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInFrame(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('frame-src');

        new ResourceDirectives(frame: "'self'; evil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInManifest(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('manifest-src');

        new ResourceDirectives(manifest: "'self'; evil");
    }

}
