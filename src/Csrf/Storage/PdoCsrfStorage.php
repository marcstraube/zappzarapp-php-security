<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection ext-pdo is optional (suggest), class only used when available
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Storage;

use Override;
use PDO;
use PDOException;
use Zappzarapp\Security\Csrf\Exception\CsrfStorageException;

/**
 * PDO-based CSRF token storage
 *
 * Supports MySQL, PostgreSQL, and SQLite. Enables distributed CSRF protection
 * backed by a relational database where Redis is not available.
 *
 * Tokens are stored under a configurable key prefix. A non-null TTL stores an
 * absolute expiry timestamp; a null TTL stores no expiry ("session lifetime"
 * semantics) by leaving expires_at NULL.
 */
final readonly class PdoCsrfStorage implements CsrfStorageInterface
{
    /**
     * Table schemas per database driver.
     *
     * Use with sprintf() to inject your table name:
     *   $pdo->exec(sprintf(PdoCsrfStorage::SCHEMA['sqlite'], 'csrf_tokens', 'csrf_tokens', 'csrf_tokens'));
     *
     * @var array<string, string>
     */
    public const array SCHEMA = [
        'mysql' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                `key` VARCHAR(255) NOT NULL PRIMARY KEY,
                `token` TEXT NOT NULL,
                `expires_at` INT UNSIGNED NULL,
                INDEX idx_expires_at (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            SQL,
        'pgsql' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                "key" VARCHAR(255) NOT NULL PRIMARY KEY,
                "token" TEXT NOT NULL,
                "expires_at" INTEGER NULL
            );
            CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s ("expires_at")
            SQL,
        'sqlite' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                "key" TEXT NOT NULL PRIMARY KEY,
                "token" TEXT NOT NULL,
                "expires_at" INTEGER NULL
            );
            CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s ("expires_at")
            SQL,
    ];

    private string $driver;

    /**
     * @param PDO $pdo PDO connection instance (must have ERRMODE_EXCEPTION)
     * @param string $table Table name for CSRF token data
     * @param string $prefix Key prefix for namespacing
     */
    public function __construct(
        private PDO $pdo,
        private string $table = 'csrf_tokens',
        private string $prefix = 'csrf:',
    ) {
        $this->driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    }

    #[Override]
    public function store(string $key, string $token, ?int $ttl = null): void
    {
        $prefixedKey = $this->prefix . $key;
        $expiresAt   = $ttl !== null ? time() + $ttl : null;

        try {
            $this->upsert($prefixedKey, $token, $expiresAt);
        } catch (PDOException $pdoException) {
            throw CsrfStorageException::writeFailed($key, $pdoException->getMessage());
        }
    }

    #[Override]
    public function retrieve(string $key): ?string
    {
        $prefixedKey = $this->prefix . $key;

        try {
            $stmt = $this->pdo->prepare(
                sprintf('SELECT "token", "expires_at" FROM %s WHERE "key" = ?', $this->table),
            );
            $stmt->execute([$prefixedKey]);

            /** @var array{token: string, expires_at: int|null}|false $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $pdoException) {
            throw CsrfStorageException::readFailed($key, $pdoException->getMessage());
        }

        if ($row === false) {
            return null;
        }

        if ($row['expires_at'] !== null && $row['expires_at'] <= time()) {
            $this->remove($key);

            return null;
        }

        return $row['token'];
    }

    #[Override]
    public function remove(string $key): void
    {
        $prefixedKey = $this->prefix . $key;

        try {
            $stmt = $this->pdo->prepare(
                sprintf('DELETE FROM %s WHERE "key" = ?', $this->table),
            );
            $stmt->execute([$prefixedKey]);
        } catch (PDOException $pdoException) {
            throw CsrfStorageException::writeFailed($key, $pdoException->getMessage());
        }
    }

    #[Override]
    public function has(string $key): bool
    {
        return $this->retrieve($key) !== null;
    }

    #[Override]
    public function clear(): void
    {
        try {
            $stmt = $this->pdo->prepare(
                sprintf('DELETE FROM %s WHERE "key" LIKE ?', $this->table),
            );
            $stmt->execute([$this->prefix . '%']);
        } catch (PDOException $pdoException) {
            throw CsrfStorageException::writeFailed('*', $pdoException->getMessage());
        }
    }

    /**
     * Remove all expired entries
     *
     * Call periodically via cron to prevent table growth. Tokens stored without
     * a TTL (expires_at IS NULL) are never removed by this method.
     *
     * @return int Number of deleted rows
     */
    public function cleanup(): int
    {
        try {
            $stmt = $this->pdo->prepare(
                sprintf('DELETE FROM %s WHERE "expires_at" IS NOT NULL AND "expires_at" <= ?', $this->table),
            );
            $stmt->execute([time()]);

            return $stmt->rowCount();
        } catch (PDOException $pdoException) {
            throw CsrfStorageException::writeFailed('*', $pdoException->getMessage());
        }
    }

    /**
     * @throws PDOException
     */
    private function upsert(string $prefixedKey, string $token, ?int $expiresAt): void
    {
        $sql = match ($this->driver) {
            'mysql' => sprintf(
                'INSERT INTO %s (`key`, `token`, `expires_at`) VALUES (?, ?, ?)'
                . ' ON DUPLICATE KEY UPDATE `token` = VALUES(`token`), `expires_at` = VALUES(`expires_at`)',
                $this->table,
            ),
            default => sprintf(
                'INSERT INTO %s ("key", "token", "expires_at") VALUES (?, ?, ?)'
                . ' ON CONFLICT ("key") DO UPDATE SET "token" = EXCLUDED."token", "expires_at" = EXCLUDED."expires_at"',
                $this->table,
            ),
        };

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$prefixedKey, $token, $expiresAt]);
    }
}
