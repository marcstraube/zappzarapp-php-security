<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\NoContextRule;

#[CoversClass(NoContextRule::class)]
final class NoContextRuleTest extends TestCase
{
    #[Test]
    public function testImplementsPolicyRuleInterface(): void
    {
        $rule = new NoContextRule([]);

        $this->assertInstanceOf(PolicyRule::class, $rule);
    }

    #[Test]
    public function testIsSatisfiedWithEmptyContextStrings(): void
    {
        $rule = new NoContextRule([]);

        $this->assertTrue($rule->isSatisfied('anypassword'));
    }

    #[Test]
    public function testIsSatisfiedWithEmptyPassword(): void
    {
        $rule = new NoContextRule(['username']);

        $this->assertTrue($rule->isSatisfied(''));
    }

    #[Test]
    public function testIsNotSatisfiedWhenPasswordContainsUsername(): void
    {
        $rule = new NoContextRule(['johndoe']);

        $this->assertFalse($rule->isSatisfied('myjohndoepassword'));
    }

    #[Test]
    public function testIsSatisfiedWhenPasswordDoesNotContainContext(): void
    {
        $rule = new NoContextRule(['johndoe']);

        $this->assertTrue($rule->isSatisfied('SecurePassword123!'));
    }

    #[Test]
    public function testCaseInsensitiveMatching(): void
    {
        $rule = new NoContextRule(['JohnDoe']);

        $this->assertFalse($rule->isSatisfied('myjohndoepassword'));
        $this->assertFalse($rule->isSatisfied('myJOHNDOEpassword'));
        $this->assertFalse($rule->isSatisfied('myJohnDoepassword'));
    }

    #[Test]
    public function testCaseInsensitiveMatchingWithUppercasePassword(): void
    {
        $rule = new NoContextRule(['johndoe']);

        $this->assertFalse($rule->isSatisfied('myJOHNDOEpassword'));
    }

    #[Test]
    public function testIgnoresContextStringsShorterThanMinMatchLength(): void
    {
        $rule = new NoContextRule(['ab', 'abc', 'abcd'], 3);

        // 'ab' should be ignored (too short), 'abc' should match
        $this->assertFalse($rule->isSatisfied('xyzabcdef'));
        $this->assertTrue($rule->isSatisfied('xyzabdef')); // no 'abc' or 'abcd'
    }

    #[Test]
    public function testCustomMinMatchLength(): void
    {
        $rule = new NoContextRule(['ab'], 2);

        $this->assertFalse($rule->isSatisfied('xyzabdef'));
    }

    #[Test]
    public function testDefaultMinMatchLengthIsThree(): void
    {
        $rule = new NoContextRule(['ab', 'abc']);

        // 'ab' is ignored (length 2 < default 3), 'abc' is checked
        $this->assertTrue($rule->isSatisfied('xyzabdef'));
        $this->assertFalse($rule->isSatisfied('xyzabcdef'));
    }

    #[Test]
    public function testMultipleContextStrings(): void
    {
        $rule = new NoContextRule(['john', 'jane', 'admin']);

        $this->assertFalse($rule->isSatisfied('password_john_123'));
        $this->assertFalse($rule->isSatisfied('jane_secure_pass'));
        $this->assertFalse($rule->isSatisfied('myadminpass'));
        $this->assertTrue($rule->isSatisfied('SecurePassword123!'));
    }

    #[Test]
    public function testContextStringsGetter(): void
    {
        $contextStrings = ['john', 'jane'];
        $rule           = new NoContextRule($contextStrings);

        $this->assertSame($contextStrings, $rule->contextStrings());
    }

    #[Test]
    public function testMinMatchLengthGetter(): void
    {
        $rule = new NoContextRule([], 5);

        $this->assertSame(5, $rule->minMatchLength());
    }

    #[Test]
    public function testDefaultMinMatchLengthGetter(): void
    {
        $rule = new NoContextRule([]);

        $this->assertSame(3, $rule->minMatchLength());
    }

    #[Test]
    public function testErrorMessage(): void
    {
        $rule = new NoContextRule(['username']);

        $this->assertSame(
            'Password must not contain personal information such as username or email',
            $rule->errorMessage()
        );
    }

    #[Test]
    public function testForUsernameFactory(): void
    {
        $rule = NoContextRule::forUsername('johndoe');

        $this->assertSame(['johndoe'], $rule->contextStrings());
        $this->assertFalse($rule->isSatisfied('myjohndoepassword'));
        $this->assertTrue($rule->isSatisfied('SecurePassword123!'));
    }

    #[Test]
    public function testForEmailFactoryExtractsLocalPartAndDomain(): void
    {
        $rule = NoContextRule::forEmail('johndoe@example.com');

        $this->assertSame(['johndoe', 'example'], $rule->contextStrings());
        $this->assertFalse($rule->isSatisfied('myjohndoepassword'));
        $this->assertFalse($rule->isSatisfied('myexamplepassword'));
        $this->assertTrue($rule->isSatisfied('SecurePassword123!'));
    }

    #[Test]
    public function testForEmailFactoryWithSubdomain(): void
    {
        $rule = NoContextRule::forEmail('user@mail.example.com');

        $this->assertSame(['user', 'mail.example'], $rule->contextStrings());
        $this->assertFalse($rule->isSatisfied('userpassword'));
        $this->assertFalse($rule->isSatisfied('mail.examplepass'));
    }

    #[Test]
    public function testForEmailFactoryWithNoAtSign(): void
    {
        $rule = NoContextRule::forEmail('invalid-email');

        $this->assertSame(['invalid-email'], $rule->contextStrings());
    }

    #[Test]
    public function testForEmailFactoryWithEmptyLocalPart(): void
    {
        $rule = NoContextRule::forEmail('@example.com');

        // Empty local part is not added, only domain
        $this->assertSame(['example'], $rule->contextStrings());
        $this->assertFalse($rule->isSatisfied('myexamplepassword'));
    }

    #[Test]
    public function testForEmailFactoryWithSinglePartDomain(): void
    {
        $rule = NoContextRule::forEmail('user@localhost');

        // Single-part domain has no TLD to remove, so only local part
        $this->assertSame(['user'], $rule->contextStrings());
    }

    #[Test]
    public function testForContextsFactory(): void
    {
        $contexts = ['john', 'jane', 'admin'];
        $rule     = NoContextRule::forContexts($contexts);

        $this->assertSame($contexts, $rule->contextStrings());
        $this->assertFalse($rule->isSatisfied('johnspassword'));
        $this->assertFalse($rule->isSatisfied('janeishere'));
        $this->assertFalse($rule->isSatisfied('adminaccess'));
        $this->assertTrue($rule->isSatisfied('SecurePassword123!'));
    }

    #[Test]
    public function testForContextsFactoryWithEmptyArray(): void
    {
        $rule = NoContextRule::forContexts([]);

        $this->assertSame([], $rule->contextStrings());
        $this->assertTrue($rule->isSatisfied('anypassword'));
    }

    #[Test]
    public function testHandlesUnicodeCharacters(): void
    {
        $rule = new NoContextRule(['mueller']);

        $this->assertFalse($rule->isSatisfied('testmueller123'));
        $this->assertTrue($rule->isSatisfied('testmuller123'));
    }

    #[Test]
    public function testHandlesUnicodeInContextString(): void
    {
        $rule = new NoContextRule(['admin']);

        $this->assertFalse($rule->isSatisfied('Admin123'));
    }

    #[Test]
    public function testUnicodeCaseInsensitiveMatching(): void
    {
        $rule = new NoContextRule(['MÜLLER']);

        $this->assertFalse($rule->isSatisfied('testmüller123'));
    }

    #[Test]
    public function testPasswordExactlyMatchesContext(): void
    {
        $rule = new NoContextRule(['password']);

        $this->assertFalse($rule->isSatisfied('password'));
    }

    #[Test]
    public function testContextAtStartOfPassword(): void
    {
        $rule = new NoContextRule(['admin']);

        $this->assertFalse($rule->isSatisfied('admin123'));
    }

    #[Test]
    public function testContextAtEndOfPassword(): void
    {
        $rule = new NoContextRule(['admin']);

        $this->assertFalse($rule->isSatisfied('super_admin'));
    }

    #[Test]
    public function testMinMatchLengthZeroMatchesAllStrings(): void
    {
        $rule = new NoContextRule(['a'], 0);

        $this->assertFalse($rule->isSatisfied('password'));
    }

    #[Test]
    public function testVeryLongContextString(): void
    {
        $longContext = str_repeat('a', 100);
        $rule        = new NoContextRule([$longContext]);

        $this->assertFalse($rule->isSatisfied($longContext));
        $this->assertTrue($rule->isSatisfied(str_repeat('a', 99)));
    }

    #[Test]
    public function testEmptyStringInContextIsIgnored(): void
    {
        $rule = new NoContextRule(['', 'valid']);

        // Empty string is less than minMatchLength (3), so ignored
        $this->assertTrue($rule->isSatisfied('anypassword'));
        $this->assertFalse($rule->isSatisfied('validpassword'));
    }

    /**
     * @return array<string, array{list<string>, string, bool}>
     */
    public static function contextMatchingProvider(): array
    {
        return [
            'no context strings'               => [[], 'anypassword', true],
            'no match'                         => [['admin'], 'SecurePass123!', true],
            'exact match'                      => [['password'], 'password', false],
            'contains at start'                => [['admin'], 'admin123', false],
            'contains at end'                  => [['admin'], '123admin', false],
            'contains in middle'               => [['admin'], 'my_admin_pass', false],
            'case insensitive upper'           => [['admin'], 'ADMIN123', false],
            'case insensitive mixed'           => [['admin'], 'AdMiN123', false],
            'multiple contexts first matches'  => [['john', 'jane'], 'john123', false],
            'multiple contexts second matches' => [['john', 'jane'], 'jane456', false],
            'multiple contexts none match'     => [['john', 'jane'], 'secure789', true],
            'short context ignored'            => [['ab'], 'xyzabdef', true],
        ];
    }

    /**
     * @param list<string> $contextStrings
     */
    #[DataProvider('contextMatchingProvider')]
    #[Test]
    public function testIsSatisfiedWithDataProvider(array $contextStrings, string $password, bool $expected): void
    {
        $rule = new NoContextRule($contextStrings);

        $this->assertSame($expected, $rule->isSatisfied($password));
    }

    /**
     * @return array<string, array{string, list<string>}>
     */
    public static function forEmailProvider(): array
    {
        return [
            'standard email'         => ['john.doe@example.com', ['john.doe', 'example']],
            'simple email'           => ['user@domain.com', ['user', 'domain']],
            'email with plus'        => ['user+tag@example.com', ['user+tag', 'example']],
            'email with numbers'     => ['user123@test.org', ['user123', 'test']],
            'no at sign'             => ['invalidEmail', ['invalidEmail']],
            'empty local part'       => ['@example.com', ['example']],
            'multiple at signs'      => ['first@second@third.com', ['first', 'second@third']],
            'subdomain email'        => ['user@mail.example.com', ['user', 'mail.example']],
            'deep subdomain'         => ['user@a.b.c.example.com', ['user', 'a.b.c.example']],
            'single part domain'     => ['user@localhost', ['user']],
            'country code tld'       => ['user@example.co.uk', ['user', 'example.co']],
        ];
    }

    /**
     * @param list<string> $expectedContext
     */
    #[DataProvider('forEmailProvider')]
    #[Test]
    public function testForEmailExtraction(string $email, array $expectedContext): void
    {
        $rule = NoContextRule::forEmail($email);

        $this->assertSame($expectedContext, $rule->contextStrings());
    }
}
