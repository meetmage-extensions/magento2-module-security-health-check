<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model;

use MeetMage\SecurityHealthCheck\Model\VersionMatcher;
use PHPUnit\Framework\TestCase;

class VersionMatcherTest extends TestCase
{
    private VersionMatcher $matcher;

    protected function setUp(): void
    {
        $this->matcher = new VersionMatcher();
    }

    public function testUnderstandsMagentoPatchVersionsInAdvisoryRanges(): void
    {
        $range = '=2.4.6|=2.4.7|<2.4.6-p13|>=2.4.7-beta1,<2.4.7-p8|>=2.4.8-beta1,<2.4.8-p3';
        $this->assertTrue($this->matcher->satisfies('2.4.8-p2', $range));
        $this->assertTrue($this->matcher->satisfies('2.4.7', $range));
        $this->assertFalse($this->matcher->satisfies('2.4.8-p3', $range));
        $this->assertFalse($this->matcher->satisfies('2.4.7-p8', $range));
        $this->assertFalse($this->matcher->satisfies('2.4.9', $range));
    }

    public function testInvalidVersionsNeverMatch(): void
    {
        $this->assertFalse($this->matcher->satisfies('dev-main', '<9.0'));
        $this->assertFalse($this->matcher->satisfies('1.2.3', ''));
        $this->assertFalse($this->matcher->isValid('1.x-dev'));
        $this->assertTrue($this->matcher->isValid('2.4.8-p3'));
    }

    public function testLatestPatchPerLineSkipsPreReleases(): void
    {
        $latest = $this->matcher->latestPatchPerLine([
            '2.4.8', '2.4.8-p1', '2.4.8-p10', '2.4.8-p2', '2.4.9-beta1', '2.4.9', '2.4.10-alpha1', '2.4.7-p9',
        ]);
        $this->assertSame(['2.4.7' => '2.4.7-p9', '2.4.8' => '2.4.8-p10', '2.4.9' => '2.4.9'], $latest);
    }

    public function testLessThanAndReleaseLine(): void
    {
        $this->assertTrue($this->matcher->lessThan('2.4.8-p2', '2.4.8-p10'));
        $this->assertFalse($this->matcher->lessThan('2.4.8-p10', '2.4.8-p2'));
        $this->assertSame('2.4.8', $this->matcher->releaseLine('2.4.8-p3'));
    }
}
