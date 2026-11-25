<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Test\Unit\Model\Check;

use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Stdlib\DateTime\DateTime;
use MeetMage\SecurityHealthCheck\Model\Check\MagentoVersion;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Lifecycle;
use MeetMage\SecurityHealthCheck\Model\Remote\DataSources;
use MeetMage\SecurityHealthCheck\Model\Severity;
use MeetMage\SecurityHealthCheck\Model\VersionMatcher;
use PHPUnit\Framework\TestCase;

class MagentoVersionTest extends TestCase
{
    private function check(string $version, ?array $advisories, bool $online = true, string $name = 'Magento'): array
    {
        $meta = $this->createMock(ProductMetadataInterface::class);
        $meta->method('getVersion')->willReturn($version);
        $meta->method('getName')->willReturn($name);
        $meta->method('getEdition')->willReturn('Community');

        $sources = $this->createMock(DataSources::class);
        $sources->method('isAvailable')->willReturn($online);
        $sources->method('getLifecycle')->willReturn([
            ['cycle' => '2.4.9', 'releaseDate' => '2026-05-12', 'eol' => false, 'support' => true],
            ['cycle' => '2.4.8', 'releaseDate' => '2025-04-03', 'eol' => false, 'support' => true,
                'extendedSupport' => '2028-05-31'],
            ['cycle' => '2.4.3', 'eol' => '2022-11-28', 'support' => '2022-11-28', 'extendedSupport' => false],
        ]);
        $sources->method('getMagentoReleases')->willReturn(['2.4.8', '2.4.8-p1', '2.4.8-p5', '2.4.3-p3', '2.4.9']);
        $sources->method('getAdvisories')->willReturn($advisories);

        $dateTime = $this->createMock(DateTime::class);
        $dateTime->method('gmtDate')->willReturn('2026-11-25');

        $findings = (new MagentoVersion($meta, $sources, new VersionMatcher(), new Lifecycle(), $dateTime))->run();
        $byCode = [];
        foreach ($findings as $finding) {
            $byCode[$finding->getCode()] = $finding;
        }
        return $byCode;
    }

    public function testOutdatedPatchWithKnownAdvisories(): void
    {
        $advisories = ['magento/community-edition' => [
            ['cve' => 'CVE-2025-1', 'severity' => 'critical', 'title' => 'RCE', 'affectedVersions' => '<2.4.8-p3'],
            ['cve' => 'CVE-2025-2', 'severity' => 'medium', 'title' => 'XSS', 'affectedVersions' => '<2.4.8-p2'],
            ['cve' => 'CVE-2025-3', 'severity' => 'high', 'title' => 'Old', 'affectedVersions' => '<2.4.7'],
        ], 'magento/project-community-edition' => [
            // the same CVE listed under the second package must not be counted twice
            ['cve' => 'CVE-2025-1', 'severity' => 'critical', 'title' => 'RCE', 'affectedVersions' => '<2.4.8-p3'],
        ]];
        $findings = $this->check('2.4.8-p1', $advisories);

        $this->assertSame(Severity::PASSED, $findings['magento_version.lifecycle']->getSeverity());
        $this->assertSame(Severity::HIGH, $findings['magento_version.patch']->getSeverity());
        $this->assertStringContainsString('2.4.8-p5', $findings['magento_version.patch']->getTitle());
        $this->assertSame(Severity::CRITICAL, $findings['magento_version.advisories']->getSeverity());
        $this->assertStringContainsString('CVE-2025-1', $findings['magento_version.advisories']->getDetail());
        $this->assertStringContainsString('CVE-2025-2', $findings['magento_version.advisories']->getDetail());
        $this->assertStringNotContainsString('CVE-2025-3', $findings['magento_version.advisories']->getDetail());
        $this->assertStringStartsWith('2 ', $findings['magento_version.advisories']->getTitle());
    }

    public function testUpToDateVersionPasses(): void
    {
        $findings = $this->check('2.4.8-p5', ['magento/community-edition' => [
            ['cve' => 'CVE-2025-1', 'severity' => 'critical', 'affectedVersions' => '<2.4.8-p3'],
        ]]);
        foreach ($findings as $finding) {
            $this->assertSame(Severity::PASSED, $finding->getSeverity(), $finding->getCode());
        }
    }

    public function testAdvisoryPublishedBeforeTheReleaseLineIsIgnored(): void
    {
        // Real case: CVE-2025-54236 (Sept 2025) lists "=2.4.9", but 2.4.9 was only released in May 2026.
        $findings = $this->check('2.4.9', ['magento/community-edition' => [
            ['cve' => 'CVE-2025-54236', 'severity' => 'critical', 'reportedAt' => '2025-09-09 12:00:00',
                'affectedVersions' => '=2.4.9|>=2.4.8-beta1,<=2.4.8-p2'],
            ['cve' => 'CVE-2026-1', 'severity' => 'high', 'reportedAt' => '2026-08-11 12:00:00',
                'affectedVersions' => '<2.4.9-p1'],
        ]]);
        $advisories = $findings['magento_version.advisories'];
        $this->assertSame(Severity::HIGH, $advisories->getSeverity());
        $this->assertSame('A known vulnerability affects your Magento version', $advisories->getTitle());
        $this->assertStringNotContainsString('CVE-2025-54236', $advisories->getDetail());

        // The same old advisory still counts for 2.4.8, which was released before it.
        $old = $this->check('2.4.8-p2', ['magento/community-edition' => [
            ['cve' => 'CVE-2025-54236', 'severity' => 'critical', 'reportedAt' => '2025-09-09 12:00:00',
                'affectedVersions' => '=2.4.9|>=2.4.8-beta1,<=2.4.8-p2'],
        ]]);
        $this->assertSame(Severity::CRITICAL, $old['magento_version.advisories']->getSeverity());
    }

    public function testEndOfLifeLineIsCritical(): void
    {
        $findings = $this->check('2.4.3-p3', []);
        $this->assertSame(Severity::CRITICAL, $findings['magento_version.lifecycle']->getSeverity());
    }

    public function testFailedLookupIsInformational(): void
    {
        $findings = $this->check('2.4.8-p5', null);
        $this->assertSame(Severity::INFO, $findings['magento_version.advisories']->getSeverity());
    }

    public function testOfflineAndUnknownPlatforms(): void
    {
        $offline = $this->check('2.4.8', [], false);
        $this->assertSame(['magento_version.offline'], array_keys($offline));

        $mageOs = $this->check('1.0.4', [], true, 'Mage-OS');
        $this->assertSame(['magento_version.unknown'], array_keys($mageOs));
        $this->assertInstanceOf(Finding::class, $mageOs['magento_version.unknown']);
    }
}
