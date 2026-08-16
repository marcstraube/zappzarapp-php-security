<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Report;

use Zappzarapp\Security\Csp\Exception\CspReportException;

/**
 * Source location a CSP violation was triggered from
 *
 * All three parts are optional: browsers omit them for violations that
 * cannot be attributed to a script position, such as a blocked stylesheet
 * referenced from the document itself.
 */
final readonly class ViolationSource
{
    use ValidatesReportFields;

    /**
     * Maximum accepted length of the source file URI
     */
    public const int MAX_FILE_LENGTH = 2048;

    /**
     * @param string $file URI of the file the violation originated from, empty when unknown
     * @param int|null $line 1-based line number, null when unknown
     * @param int|null $column 1-based column number, null when unknown
     *
     * @throws CspReportException If a value is unsafe, too long or negative
     */
    public function __construct(
        public string $file = '',
        public ?int $line = null,
        public ?int $column = null,
    ) {
        $this->assertClean('source-file', $this->file, self::MAX_FILE_LENGTH);
        $this->assertNonNegative('line-number', $this->line);
        $this->assertNonNegative('column-number', $this->column);
    }

    /**
     * Convert to log context fields
     *
     * @return array{source_file: string|null, line_number: int|null, column_number: int|null}
     */
    public function toLogContext(): array
    {
        return [
            'source_file'   => $this->file !== '' ? $this->file : null,
            'line_number'   => $this->line,
            'column_number' => $this->column,
        ];
    }
}
