<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Check;

use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\InstalledPackages;
use MeetMage\SecurityHealthCheck\Model\Remote\DataSources;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Severity;
use MeetMage\SecurityHealthCheck\Model\VersionMatcher;

/**
 * Installed Composer packages (extensions and libraries) with known security advisories.
 * Like "composer audit", but in the admin and on a schedule.
 */
class ComposerPackages implements CheckInterface
{
    /**
     * Core metapackages are covered by the Magento version check.
     */
    private const SKIP = ['magento/community-edition', 'magento/project-community-edition'];

    /**
     * @var InstalledPackages
     */
    private InstalledPackages $installed;

    /**
     * @var DataSources
     */
    private DataSources $sources;

    /**
     * @var VersionMatcher
     */
    private VersionMatcher $versions;

    /**
     * @param InstalledPackages $installed
     * @param DataSources $sources
     * @param VersionMatcher $versions
     */
    public function __construct(InstalledPackages $installed, DataSources $sources, VersionMatcher $versions)
    {
        $this->installed = $installed;
        $this->sources = $sources;
        $this->versions = $versions;
    }

    /**
     * @inheritDoc
     */
    public function run(): array
    {
        $packages = array_diff_key($this->installed->getVersions(), array_flip(self::SKIP));
        if (!$packages) {
            return [new Finding(
                'packages.advisories',
                Report::CATEGORY_PACKAGES,
                Severity::INFO,
                (string) __('Composer packages not checked'),
                (string) __('No Composer package list was found (vendor/composer/installed.json).')
            )];
        }
        $advisories = $this->sources->getAdvisories(array_keys($packages));
        if ($advisories === null) {
            return [new Finding(
                'packages.advisories',
                Report::CATEGORY_PACKAGES,
                Severity::INFO,
                (string) __('Composer packages not checked'),
                (string) __('External lookups are off or Packagist did not answer.')
            )];
        }

        $findings = [];
        foreach ($advisories as $package => $list) {
            $version = $packages[$package] ?? '';
            $hits = [];
            foreach ($list as $advisory) {
                if ($this->versions->satisfies($version, (string) ($advisory['affectedVersions'] ?? ''))) {
                    $hits[] = $advisory;
                }
            }
            if ($hits) {
                $findings[] = $this->packageFinding($package, $version, $hits);
            }
        }

        if (!$findings) {
            return [new Finding(
                'packages.advisories',
                Report::CATEGORY_PACKAGES,
                Severity::PASSED,
                (string) __('No known vulnerabilities in %1 Composer packages', count($packages)),
                (string) __('Checked against the Packagist security advisory database.')
            )];
        }
        return $findings;
    }

    /**
     * One finding per vulnerable package.
     *
     * @param string $package
     * @param string $version
     * @param array<int,array<string,mixed>> $hits
     * @return Finding
     */
    private function packageFinding(string $package, string $version, array $hits): Finding
    {
        $worst = Severity::LOW;
        $parts = [];
        foreach ($hits as $advisory) {
            $severity = strtolower((string) ($advisory['severity'] ?? ''));
            if (!in_array($severity, [Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW], true)) {
                $severity = Severity::HIGH;
            }
            if (Severity::RANK[$severity] < Severity::RANK[$worst]) {
                $worst = $severity;
            }
            $id = (string) ($advisory['cve'] ?? '') ?: (string) ($advisory['remoteId'] ?? '');
            $parts[] = trim(sprintf('%s (%s): %s', $id, $severity, (string) ($advisory['title'] ?? '')));
        }
        $link = (string) ($hits[0]['link'] ?? '');
        return new Finding(
            'packages.advisories.' . $package,
            Report::CATEGORY_PACKAGES,
            $worst,
            count($hits) === 1
                ? (string) __('%1 %2 has a known vulnerability', $package, $version)
                : (string) __('%1 %2 has %3 known vulnerabilities', $package, $version, count($hits)),
            implode('; ', array_slice($parts, 0, 10)) . (count($parts) > 10 ? ' …' : ''),
            (string) __('Update it: composer update %1 --with-dependencies, then test on staging. If no fixed '
                . 'version exists, ask the vendor or replace the package.', $package),
            str_starts_with($link, 'https://') ? $link : 'https://packagist.org/packages/' . $package . '/advisories'
        );
    }
}
