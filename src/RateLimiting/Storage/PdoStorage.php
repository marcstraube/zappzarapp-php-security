<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection ext-pdo is optional (suggest), class only used when available
 */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

use JsonException;
use Override;
use PDO;
use PDOException;
use Zappzarapp\Security\RateLimiting\Exception\StorageException;

/**
 * PDO-based rate limit storage
 *
 * Supports MySQL, PostgreSQL, and SQLite. For environments without Redis
 * or Memcached. Uses database-level locking for atomic operations.
 */
final readonly class PdoStorage implements RateLimitStorage
{
    /**
     * Table schemas per database driver.
     *
     * Use with sprintf() to inject your table name:
     *   $pdo->exec(sprintf(PdoStorage::SCHEMA['sqlite'], 'rate_limits'));
     *
     * @var array<string, string>
     */
    public const array SCHEMA = [
        'mysql' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                `key` VARCHAR(255) NOT NULL PRIMARY KEY,
                `data` TEXT NOT NULL,
                `expires_at` INT UNSIGNED NOT NULL,
                INDEX idx_expires_at (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            SQL,
        'pgsql' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                "key" VARCHAR(255) NOT NULL PRIMARY KEY,
                "data" TEXT NOT NULL,
                "expires_at" INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s ("expires_at")
            SQL,
        'sqlite' => <<<'SQL'
            CREATE TABLE IF NOT EXISTS %s (
                "key" TEXT NOT NULL PRIMARY KEY,
                "data" TEXT NOT NULL,
                "expires_at" INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_%s_expires_at ON %s ("expires_at")
            SQL,
    ];

    private string $driver;

    /**
     * @param PDO $pdo PDO connection instance (must have ERRMODE_EXCEPTION)
     * @param string $table Table name for rate limit data
     * @param string $prefix Key prefix for namespacing
     */
    public function __construct(
        private PDO $pdo,
        private string $table = 'rate_limits',
        private string $prefix = 'ratelimit:',
    ) {
        $this->driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    }

    #[Override]
    public function get(string $key): ?array
    {
        $prefixedKey = $this->prefix . $key;

        try {
            $stmt = $this->pdo->prepare(
                sprintf('SELECT "data", "expires_at" FROM %s WHERE "key" = ?', $this->table),
            );
            $stmt->execute([$prefixedKey]);

            /** @var array{data: string, expires_at: int}|false $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $pdoException) {
            throw StorageException::readFailed($key, $pdoException->getMessage());
        }

        if ($row === false) {
            return null;
        }

        if ($row['expires_at'] <= time()) {
            $this->delete($key);

            return null;
        }

        $decoded = json_decode($row['data'], true);

        return is_array($decoded) ? $decoded : null;
    }

    #[Override]
    public function set(string $key, array $data, int $ttl): void
    {
        try {
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw StorageException::writeFailed($key, $jsonException->getMessage());
        }

        $prefixedKey = $this->prefix . $key;
        $expiresAt   = time() + $ttl;

        try {
            $this->upsert($prefixedKey, $encoded, $expiresAt);
        } catch (PDOException $pdoException) {
            throw StorageException::writeFailed($key, $pdoException->getMessage());
        }
    }

    #[Override]
    public function delete(string $key): void
    {
        $prefixedKey = $this->prefix . $key;

        try {
            $stmt = $this->pdo->prepare(
                sprintf('DELETE FROM %s WHERE "key" = ?', $this->table),
            );
            $stmt->execute([$prefixedKey]);
        } catch (PDOException $pdoException) {
            throw StorageException::writeFailed($key, $pdoException->getMessage());
        }
    }

    #[Override]
    public function increment(string $key, int $amount, int $ttl): int
    {
        $prefixedKey = $this->prefix . $key;
        $expiresAt   = time() + $ttl;

        try {
            if ($this->driver === 'sqlite') {
                $this->pdo->exec('BEGIN IMMEDIATE');
            } else {
                $this->pdo->beginTransaction();
            }

            $current = $this->fetchCounterForUpdate($prefixedKey);

            if ($current === null) {
                $this->upsert($prefixedKey, (string) $amount, $expiresAt);
                $this->commitTransaction();

                return $amount;
            }

            $newValue = $current + $amount;

            $stmt = $this->pdo->prepare(
                sprintf('UPDATE %s SET "data" = ?, "expires_at" = ? WHERE "key" = ?', $this->table),
            );
            $stmt->execute([(string) $newValue, $expiresAt, $prefixedKey]);

            $this->commitTransaction();

            return $newValue;
        } catch (PDOException $pdoException) {
            $this->rollbackTransaction();

            throw StorageException::writeFailed($key, $pdoException->getMessage());
        }
    }

    /**
     * Remove all expired entries
     *
     * Call periodically via cron to prevent table growth.
     *
     * @return int Number of deleted rows
     */
    public function cleanup(): int
    {
        try {
            $stmt = $this->pdo->prepare(
                sprintf('DELETE FROM %s WHERE "expires_at" <= ?', $this->table),
            );
            $stmt->execute([time()]);

            return $stmt->rowCount();
        } catch (PDOException $pdoException) {
            throw StorageException::writeFailed('*', $pdoException->getMessage());
        }
    }

    /**
     * @throws PDOException
     */
    private function upsert(string $prefixedKey, string $data, int $expiresAt): void
    {
        $sql = match ($this->driver) {
            'mysql' => sprintf(
                'INSERT INTO %s (`key`, `data`, `expires_at`) VALUES (?, ?, ?)'
                . ' ON DUPLICATE KEY UPDATE `data` = VALUES(`data`), `expires_at` = VALUES(`expires_at`)',
                $this->table,
            ),
            default => sprintf(
                'INSERT INTO %s ("key", "data", "expires_at") VALUES (?, ?, ?)'
                . ' ON CONFLICT ("key") DO UPDATE SET "data" = EXCLUDED."data", "expires_at" = EXCLUDED."expires_at"',
                $this->table,
            ),
        };

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$prefixedKey, $data, $expiresAt]);
    }

    private function fetchCounterForUpdate(string $prefixedKey): ?int
    {
        if ($this->driver === 'mysql') {
            $sql = sprintf('SELECT "data", "expires_at" FROM %s WHERE "key" = ? FOR UPDATE', $this->table);
        } else {
            $sql = sprintf('SELECT "data", "expires_at" FROM %s WHERE "key" = ?', $this->table);
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$prefixedKey]);

        /** @var array{data: string, expires_at: int}|false $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false || $row['expires_at'] <= time()) {
            return null;
        }

        return (int) $row['data'];
    }

    private function commitTransaction(): void
    {
        $this->pdo->commit();
    }

    private function rollbackTransaction(): void
    {
        try {
            $this->pdo->rollBack();
        } catch (PDOException) {
            // Rollback may fail if transaction was already rolled back
        }
    }
}
