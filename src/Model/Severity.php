<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

/**
 * Severity levels for findings, with the points each one costs in the health score.
 */
class Severity
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const PASSED = 'passed';
    public const INFO = 'info';

    /**
     * Points subtracted from 100 per finding. Only these severities count as issues.
     */
    public const PENALTY = [
        self::CRITICAL => 25,
        self::HIGH => 10,
        self::MEDIUM => 4,
        self::LOW => 1,
    ];

    /**
     * Sort order, most serious first.
     */
    public const RANK = [
        self::CRITICAL => 0,
        self::HIGH => 1,
        self::MEDIUM => 2,
        self::LOW => 3,
        self::INFO => 4,
        self::PASSED => 5,
    ];
}
