#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Check for classes and methods with 0% test coverage
 *
 * Usage: php bin/check-coverage.php build/coverage.xml
 */

if ($argc < 2) {
    echo "Usage: php bin/check-coverage.php <coverage.xml>\n";
    exit(1);
}

$file = $argv[1];

if (!file_exists($file)) {
    echo "Error: Coverage file not found: {$file}\n";
    exit(1);
}

$xml = simplexml_load_file($file);
if ($xml === false) {
    echo "Error: Failed to parse XML\n";
    exit(1);
}

$uncoveredClasses = [];
$uncoveredMethods = [];

foreach ($xml->xpath('//file') as $fileNode) {
    $filePath = (string) $fileNode['name'];

    // Skip test files
    if (str_contains($filePath, '/tests/')) {
        continue;
    }

    foreach ($fileNode->class as $class) {
        $className = (string) $class['name'];
        $metrics = $class->metrics;

        if ($metrics === null) {
            continue;
        }

        $methods = (int) $metrics['methods'];
        $coveredMethods = (int) $metrics['coveredmethods'];

        // Check for completely uncovered classes
        if ($methods > 0 && $coveredMethods === 0) {
            $uncoveredClasses[] = $className;
            continue; // Don't list individual methods for uncovered classes
        }

        // Check for uncovered methods in partially covered classes
        if ($coveredMethods > 0 && $coveredMethods < $methods) {
            foreach ($fileNode->line as $line) {
                if ((string) $line['type'] === 'method' && (int) $line['count'] === 0) {
                    $methodName = (string) $line['name'];
                    $uncoveredMethods[] = "{$className}::{$methodName}()";
                }
            }
        }
    }
}

$hasErrors = false;

if ($uncoveredClasses !== []) {
    echo "ERROR: The following classes have 0% test coverage:\n\n";
    foreach ($uncoveredClasses as $class) {
        echo "  - {$class}\n";
    }
    echo "\n";
    $hasErrors = true;
}

if ($uncoveredMethods !== []) {
    echo "ERROR: The following methods have 0% test coverage:\n\n";
    foreach ($uncoveredMethods as $method) {
        echo "  - {$method}\n";
    }
    echo "\n";
    $hasErrors = true;
}

if ($hasErrors) {
    echo "Add tests for these classes/methods or remove them if unused.\n";
    exit(1);
}

echo "OK: All classes and methods have test coverage.\n";
exit(0);
