<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model\Check;

use MeetMage\SecurityHealthCheck\Model\Check\ComposerPackages;
use MeetMage\SecurityHealthCheck\Model\InstalledPackages;
use MeetMage\SecurityHealthCheck\Model\Remote\DataSources;
use MeetMage\SecurityHealthCheck\Model\Severity;
use MeetMage\SecurityHealthCheck\Model\VersionMatcher;
use PHPUnit\Framework\TestCase;

class ComposerPackagesTest extends TestCase
{
    private function runCheck(array $installed, ?array $advisories, ?array &$sentNames = null): array
    {
        $packages = $this->createMock(InstalledPackages::class);
        $packages->method('getVersions')->willReturn($installed);
        $sources = $this->createMock(DataSources::class);
        $sources->method('getAdvisories')->willReturnCallback(
            static function (array $names) use ($advisories, &$sentNames) {
                $sentNames = $names;
                return $advisories;
            }
        );
        return (new ComposerPackages($packages, $sources, new VersionMatcher()))->run();
    }

    public function testReportsOnlyAffectedPackagesAndSendsNamesOnly(): void
    {
        $sent = null;
        $findings = $this->runCheck(
            [
                'guzzlehttp/guzzle' => '7.4.0',
                'monolog/monolog' => '3.5.0',
                'magento/community-edition' => '2.4.8',
            ],
            [
                'guzzlehttp/guzzle' => [
                    ['cve' => 'CVE-2022-31090', 'severity' => 'high', 'title' => 'Leak', 'affectedVersions' => '<7.4.5'],
                    ['cve' => 'CVE-2022-29248', 'severity' => 'critical', 'title' => 'Cookies', 'affectedVersions' => '<7.4.3'],
                ],
                'monolog/monolog' => [
                    ['cve' => 'CVE-2000-1', 'severity' => 'low', 'title' => 'Old', 'affectedVersions' => '<2.0.0'],
                ],
            ],
            $sent
        );

        $this->assertSame(['guzzlehttp/guzzle', 'monolog/monolog'], $sent, 'core metapackage skipped, names only');
        $this->assertCount(1, $findings);
        $this->assertSame('packages.advisories.guzzlehttp/guzzle', $findings[0]->getCode());
        $this->assertSame(Severity::CRITICAL, $findings[0]->getSeverity());
        $this->assertStringContainsString('2 known vulnerabilities', $findings[0]->getTitle());
    }

    public function testCleanPackagesPass(): void
    {
        $findings = $this->runCheck(['monolog/monolog' => '3.5.0'], []);
        $this->assertSame(Severity::PASSED, $findings[0]->getSeverity());
    }

    public function testLookupFailureIsInformational(): void
    {
        $findings = $this->runCheck(['monolog/monolog' => '3.5.0'], null);
        $this->assertSame(Severity::INFO, $findings[0]->getSeverity());
    }

    public function testUnknownSeverityCountsAsHigh(): void
    {
        $findings = $this->runCheck(
            ['vendor/module' => '1.0.0'],
            ['vendor/module' => [['remoteId' => 'GHSA-x', 'severity' => null, 'affectedVersions' => '<1.1']]]
        );
        $this->assertSame(Severity::HIGH, $findings[0]->getSeverity());
        $this->assertStringContainsString('GHSA-x', $findings[0]->getDetail());
    }
}
