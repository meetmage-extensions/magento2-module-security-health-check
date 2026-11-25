<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model;

use Magento\Framework\FlagManager;
use Magento\Framework\Stdlib\DateTime\DateTime;
use MeetMage\SecurityHealthCheck\Model\Check\CheckInterface;
use MeetMage\SecurityHealthCheck\Model\Config;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Remote\JsonClient;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\ReportCodec;
use MeetMage\SecurityHealthCheck\Model\Scanner;
use MeetMage\SecurityHealthCheck\Model\Severity;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class ScannerTest extends TestCase
{
    public function testRunsChecksAppliesIgnoreListAndStoresReport(): void
    {
        $check = $this->createMock(CheckInterface::class);
        $check->method('run')->willReturn([
            new Finding('admin.captcha', Report::CATEGORY_ADMIN, Severity::LOW, 'No captcha'),
            new Finding('packages.advisories.foo/bar', Report::CATEGORY_PACKAGES, Severity::HIGH, 'foo'),
            new Finding('admin.2fa', Report::CATEGORY_ADMIN, Severity::HIGH, 'No 2FA'),
        ]);
        $broken = $this->createMock(CheckInterface::class);
        $broken->method('run')->willThrowException(new \RuntimeException('boom'));

        $config = $this->createMock(Config::class);
        $config->method('getIgnoredChecks')->willReturn(['admin.captcha', 'packages.advisories.foo/*']);

        $stored = [];
        $flags = $this->createMock(FlagManager::class);
        $flags->method('getFlagData')->willReturn(null);
        $flags->method('saveFlag')->willReturnCallback(static function (string $code, $data) use (&$stored) {
            $stored[$code] = $data;
            return true;
        });
        $dateTime = $this->createMock(DateTime::class);
        $dateTime->method('gmtDate')->willReturn('2026-11-25 04:23:00');

        $scanner = new Scanner(
            $flags,
            $dateTime,
            $config,
            $this->createMock(JsonClient::class),
            $this->createMock(LoggerInterface::class),
            new ReportCodec(),
            ['main' => $check, 'broken' => $broken, 'not_a_check' => new \stdClass()]
        );
        $report = $scanner->scan();

        $codes = array_map(static fn (Finding $f): string => $f->getCode(), $report->getFindings());
        $this->assertSame(['admin.2fa', 'check_error.broken'], $codes);
        $this->assertSame(90, $report->getScore());
        $this->assertArrayHasKey(Scanner::FLAG_REPORT, $stored);
        $this->assertArrayNotHasKey(Scanner::FLAG_PREVIOUS, $stored, 'nothing to keep before the first run');
    }
}
