<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;

/**
 * Tests for ResourceDirectives value preservation in with* methods
 *
 * These tests ensure cloneWith() correctly preserves unchanged values
 * and kills mutation testing ?? swap mutations.
 */
final class ResourceDirectivesPreservationTest extends TestCase
{
    public function testWithImgPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            img: "'self' data:",
            font: "'self' https://fonts.com",
            connect: "'self' wss://",
            media: "'self' https://media.com",
            worker: "'self' blob:",
            child: "'self' https://child.com",
            frame: "'self' https://frame.com",
            manifest: "'self'"
        );

        $modified = $original->withImg("'none'");

        $this->assertSame("'none'", $modified->img);
        $this->assertSame("'self' https://fonts.com", $modified->font);
        $this->assertSame("'self' wss://", $modified->connect);
        $this->assertSame("'self' https://media.com", $modified->media);
        $this->assertSame("'self' blob:", $modified->worker);
        $this->assertSame("'self' https://child.com", $modified->child);
        $this->assertSame("'self' https://frame.com", $modified->frame);
        $this->assertSame("'self'", $modified->manifest);
    }

    public function testWithFontPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            img: "'self' https://img.com",
            font: "'self'",
            connect: "'self' https://api.com",
        );

        $modified = $original->withFont("'none'");

        $this->assertSame("'self' https://img.com", $modified->img);
        $this->assertSame("'none'", $modified->font);
        $this->assertSame("'self' https://api.com", $modified->connect);
    }

    public function testWithConnectPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            img: "'self' https://img.com",
            font: "'self' https://fonts.com",
            connect: "'self'",
            media: "'self' https://media.com",
        );

        $modified = $original->withConnect("'none'");

        $this->assertSame("'self' https://img.com", $modified->img);
        $this->assertSame("'self' https://fonts.com", $modified->font);
        $this->assertSame("'none'", $modified->connect);
        $this->assertSame("'self' https://media.com", $modified->media);
    }

    public function testWithMediaPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            connect: "'self' https://api.com",
            media: "'self'",
            worker: "'self' blob:",
        );

        $modified = $original->withMedia("'none'");

        $this->assertSame("'self' https://api.com", $modified->connect);
        $this->assertSame("'none'", $modified->media);
        $this->assertSame("'self' blob:", $modified->worker);
    }

    public function testWithWorkerPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            media: "'self' https://media.com",
            worker: "'self'",
            child: "'self' https://child.com",
        );

        $modified = $original->withWorker("'none'");

        $this->assertSame("'self' https://media.com", $modified->media);
        $this->assertSame("'none'", $modified->worker);
        $this->assertSame("'self' https://child.com", $modified->child);
    }

    public function testWithChildPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            worker: "'self' blob:",
            child: "'self'",
            frame: "'self' https://frame.com",
        );

        $modified = $original->withChild("'none'");

        $this->assertSame("'self' blob:", $modified->worker);
        $this->assertSame("'none'", $modified->child);
        $this->assertSame("'self' https://frame.com", $modified->frame);
    }

    public function testWithFramePreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            child: "'self' https://child.com",
            frame: "'self'",
            manifest: "'self' https://manifest.com",
        );

        $modified = $original->withFrame("'none'");

        $this->assertSame("'self' https://child.com", $modified->child);
        $this->assertSame("'none'", $modified->frame);
        $this->assertSame("'self' https://manifest.com", $modified->manifest);
    }

    public function testWithManifestPreservesOtherValues(): void
    {
        $original = new ResourceDirectives(
            frame: "'self' https://frame.com",
            manifest: "'self'",
        );

        $modified = $original->withManifest("'none'");

        $this->assertSame("'self' https://frame.com", $modified->frame);
        $this->assertSame("'none'", $modified->manifest);
    }
}
