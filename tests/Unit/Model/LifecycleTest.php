<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model;

use MeetMage\SecurityHealthCheck\Model\Lifecycle;
use PHPUnit\Framework\TestCase;

class LifecycleTest extends TestCase
{
    private const CYCLES = [
        ['cycle' => '2.4.9', 'eol' => false, 'support' => true, 'extendedSupport' => '2029-05-31'],
        ['cycle' => '2.4.6', 'eol' => false, 'support' => true, 'extendedSupport' => '2027-01-31'],
        ['cycle' => '2.4.5', 'eol' => '2024-11-25', 'support' => '2024-11-25', 'extendedSupport' => '2027-08-11'],
        ['cycle' => '2.4.3', 'eol' => '2022-11-28', 'support' => '2022-11-28', 'extendedSupport' => false],
        ['cycle' => '8.2', 'eol' => '2026-12-31', 'support' => '2024-12-31'],
        ['cycle' => '8.3', 'eol' => '2027-12-31', 'support' => '2025-12-31'],
    ];

    /**
     * @dataProvider statusProvider
     */
    public function testStatus(string $cycle, string $expected): void
    {
        $this->assertSame($expected, (new Lifecycle())->evaluate(self::CYCLES, $cycle, '2026-11-25')['status']);
    }

    public static function statusProvider(): array
    {
        return [
            'supported' => ['2.4.9', Lifecycle::SUPPORTED],
            'extended support ends within 180 days' => ['2.4.6', Lifecycle::ENDING_SOON],
            'past eol but extended support' => ['2.4.5', Lifecycle::EXTENDED],
            'end of life' => ['2.4.3', Lifecycle::END_OF_LIFE],
            'php eol soon' => ['8.2', Lifecycle::ENDING_SOON],
            'php security fixes only' => ['8.3', Lifecycle::SECURITY_ONLY],
            'unknown' => ['1.9', Lifecycle::UNKNOWN],
        ];
    }

    public function testNewestCycle(): void
    {
        $this->assertSame('8.3', (new Lifecycle())->newestCycle(self::CYCLES));
    }
}
