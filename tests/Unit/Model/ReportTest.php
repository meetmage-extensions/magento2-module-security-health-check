<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model;

use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\ReportCodec;
use MeetMage\SecurityHealthCheck\Model\Severity;
use PHPUnit\Framework\TestCase;

class ReportTest extends TestCase
{
    private function report(): Report
    {
        return new Report([
            new Finding('b.passed', Report::CATEGORY_ADMIN, Severity::PASSED, 'OK'),
            new Finding('a.low', Report::CATEGORY_ADMIN, Severity::LOW, 'Low'),
            new Finding('c.critical', Report::CATEGORY_PLATFORM, Severity::CRITICAL, 'Critical'),
            new Finding('d.high', Report::CATEGORY_CONFIG, Severity::HIGH, 'High'),
            new Finding('e.info', Report::CATEGORY_CONFIG, 'unknown-level', 'Info'),
        ], '2026-11-25 04:23:00');
    }

    public function testScoreSubtractsPenalties(): void
    {
        $this->assertSame(100 - 25 - 10 - 1, $this->report()->getScore());
    }

    public function testScoreNeverBelowZero(): void
    {
        $findings = array_fill(0, 6, new Finding('x', Report::CATEGORY_PLATFORM, Severity::CRITICAL, 'x'));
        $this->assertSame(0, (new Report($findings, ''))->getScore());
    }

    public function testFindingsSortedMostSeriousFirst(): void
    {
        $codes = array_map(static fn (Finding $f): string => $f->getCode(), $this->report()->getFindings());
        $this->assertSame(['c.critical', 'd.high', 'a.low', 'e.info', 'b.passed'], $codes);
    }

    public function testIssueCodesRespectMinimumSeverity(): void
    {
        $this->assertSame(['c.critical', 'd.high'], $this->report()->issueCodes(Severity::HIGH));
        $this->assertSame(['c.critical', 'd.high', 'a.low'], $this->report()->issueCodes());
    }

    public function testRoundTripThroughArray(): void
    {
        $report = $this->report();
        $copy = (new ReportCodec())->toReport($report->toArray());
        $this->assertEquals($report->toArray(), $copy->toArray());
        $this->assertSame(Severity::INFO, $copy->getFindings()[3]->getSeverity());
    }
}
