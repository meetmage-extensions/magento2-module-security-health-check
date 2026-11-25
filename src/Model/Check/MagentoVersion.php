<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Check;

use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Stdlib\DateTime\DateTime;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Lifecycle;
use MeetMage\SecurityHealthCheck\Model\Remote\DataSources;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Severity;
use MeetMage\SecurityHealthCheck\Model\VersionMatcher;

/**
 * Is this Magento version still supported, on the latest security patch, and free of known advisories?
 */
class MagentoVersion implements CheckInterface
{
    /**
     * Advisories for the Magento core are published under these Composer names.
     */
    private const CORE_PACKAGES = ['magento/community-edition', 'magento/project-community-edition'];

    private const RELEASE_INFO = 'https://experienceleague.adobe.com/en/docs/commerce-operations/release/versions';

    /**
     * @var ProductMetadataInterface
     */
    private ProductMetadataInterface $productMetadata;

    /**
     * @var DataSources
     */
    private DataSources $sources;

    /**
     * @var VersionMatcher
     */
    private VersionMatcher $versions;

    /**
     * @var Lifecycle
     */
    private Lifecycle $lifecycle;

    /**
     * @var DateTime
     */
    private DateTime $dateTime;

    /**
     * @param ProductMetadataInterface $productMetadata
     * @param DataSources $sources
     * @param VersionMatcher $versions
     * @param Lifecycle $lifecycle
     * @param DateTime $dateTime
     */
    public function __construct(
        ProductMetadataInterface $productMetadata,
        DataSources $sources,
        VersionMatcher $versions,
        Lifecycle $lifecycle,
        DateTime $dateTime
    ) {
        $this->productMetadata = $productMetadata;
        $this->sources = $sources;
        $this->versions = $versions;
        $this->lifecycle = $lifecycle;
        $this->dateTime = $dateTime;
    }

    /**
     * @inheritDoc
     */
    public function run(): array
    {
        $version = (string) $this->productMetadata->getVersion();
        $name = (string) $this->productMetadata->getName();
        $edition = (string) $this->productMetadata->getEdition();
        $label = trim($name . ' ' . $edition . ' ' . $version);

        if (stripos($name, 'magento') === false || !$this->versions->isValid($version)) {
            return [new Finding(
                'magento_version.unknown',
                Report::CATEGORY_PLATFORM,
                Severity::INFO,
                (string) __('Platform version not checked'),
                (string) __('%1 is not a Magento Open Source or Adobe Commerce version this check can compare.', $label)
            )];
        }
        if (!$this->sources->isAvailable()) {
            return [new Finding(
                'magento_version.offline',
                Report::CATEGORY_PLATFORM,
                Severity::INFO,
                (string) __('Version lookups are switched off'),
                (string) __('Installed: %1. Turn on "Look up public security data" to compare it with the latest '
                    . 'releases and known vulnerabilities.', $label)
            )];
        }

        $line = $this->versions->releaseLine($version);
        return array_merge(
            $this->checkLifecycle($label, $line),
            $this->checkLatestPatch($label, $version, $line),
            $this->checkAdvisories($label, $version, $this->lineReleaseDate($line))
        );
    }

    /**
     * First release date of a release line (Y-m-d), from endoflife.date.
     *
     * @param string $line
     * @return string
     */
    private function lineReleaseDate(string $line): string
    {
        foreach ($this->sources->getLifecycle('magento') ?? [] as $cycle) {
            if ((string) ($cycle['cycle'] ?? '') === $line) {
                $date = (string) ($cycle['releaseDate'] ?? '');
                return preg_match('/^\d{4}-\d{2}-\d{2}$/', $date) ? $date : '';
            }
        }
        return '';
    }

    /**
     * End-of-life status of the release line.
     *
     * @param string $label
     * @param string $line
     * @return Finding[]
     */
    private function checkLifecycle(string $label, string $line): array
    {
        $cycles = $this->sources->getLifecycle('magento');
        if ($cycles === null) {
            return [$this->unavailable('magento_version.lifecycle', __('Support dates could not be loaded'))];
        }
        $info = $this->lifecycle->evaluate($cycles, $line, $this->dateTime->gmtDate('Y-m-d'));
        $newest = $this->lifecycle->newestCycle($cycles);
        $code = 'magento_version.lifecycle';
        switch ($info['status']) {
            case Lifecycle::END_OF_LIFE:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::CRITICAL,
                    (string) __('Magento %1 is end of life', $line),
                    (string) __(
                        '%1 stopped receiving security patches on %2.',
                        $label,
                        $info['extended'] ?: $info['eol']
                    ),
                    (string) __('Upgrade to a supported release line (newest: %1). Until then, new vulnerabilities '
                        . 'in your version will not be fixed.', $newest),
                    self::RELEASE_INFO
                )];
            case Lifecycle::EXTENDED:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::HIGH,
                    (string) __('Magento %1 is past regular support', $line),
                    (string) __(
                        'Regular support ended on %1. Extended support (Adobe Commerce) ends on %2.',
                        $info['eol'],
                        $info['extended']
                    ),
                    (string) __(
                        'Plan the upgrade to %1 now; Magento Open Source does not get extended support.',
                        $newest
                    ),
                    self::RELEASE_INFO
                )];
            case Lifecycle::SECURITY_ONLY:
            case Lifecycle::ENDING_SOON:
                $end = $info['eol'] ?: $info['extended'];
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::MEDIUM,
                    (string) __('Magento %1 support ends soon', $line),
                    (string) __('Security support for %1 ends on %2.', $line, $end),
                    (string) __('Schedule the upgrade to %1 before that date.', $newest),
                    self::RELEASE_INFO
                )];
            case Lifecycle::SUPPORTED:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::PASSED,
                    (string) __('Magento %1 is a supported release line', $line),
                    (string) __(
                        'Security support continues until %1.',
                        $info['eol'] ?: $info['extended'] ?: __('a date not yet announced')
                    )
                )];
            default:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::INFO,
                    (string) __('Support dates for Magento %1 are not listed yet', $line),
                    (string) __('endoflife.date has no entry for this release line.')
                )];
        }
    }

    /**
     * Is the installed version the newest patch of its release line?
     *
     * @param string $label
     * @param string $version
     * @param string $line
     * @return Finding[]
     */
    private function checkLatestPatch(string $label, string $version, string $line): array
    {
        $releases = $this->sources->getMagentoReleases();
        if ($releases === null) {
            return [$this->unavailable('magento_version.patch', __('The Magento release list could not be loaded'))];
        }
        $latest = $this->versions->latestPatchPerLine($releases)[$line] ?? '';
        if ($latest === '') {
            return [];
        }
        if ($this->versions->lessThan($version, $latest)) {
            return [new Finding(
                'magento_version.patch',
                Report::CATEGORY_PLATFORM,
                Severity::HIGH,
                (string) __('Security patch %1 is not installed', $latest),
                (string) __('You run %1. The newest patch release for %2 is %3.', $label, $line, $latest),
                (string) __('Upgrade to %1 with Composer and test on staging first. Patch releases contain '
                    . 'security fixes only, so they are the quickest upgrade to make.', $latest),
                self::RELEASE_INFO
            )];
        }
        return [new Finding(
            'magento_version.patch',
            Report::CATEGORY_PLATFORM,
            Severity::PASSED,
            (string) __('Latest security patch installed'),
            (string) __('%1 is the newest patch release for %2.', $version, $line)
        )];
    }

    /**
     * Known vulnerabilities that affect the installed version.
     *
     * @param string $label
     * @param string $version
     * @param string $lineReleased First release date of the installed release line (Y-m-d), if known
     * @return Finding[]
     */
    private function checkAdvisories(string $label, string $version, string $lineReleased): array
    {
        $advisories = $this->sources->getAdvisories(self::CORE_PACKAGES);
        if ($advisories === null) {
            return [$this->unavailable('magento_version.advisories', __('Known vulnerabilities could not be loaded'))];
        }
        $matches = [];
        foreach (self::CORE_PACKAGES as $package) {
            foreach ($advisories[$package] ?? [] as $advisory) {
                $id = (string) ($advisory['cve'] ?? '')
                    ?: (string) ($advisory['remoteId'] ?? $advisory['advisoryId'] ?? '');
                if (isset($matches[$id])
                    || !$this->versions->satisfies($version, (string) ($advisory['affectedVersions'] ?? ''))) {
                    continue;
                }
                // Advisories published before this release line came out sometimes list its unreleased
                // version (e.g. "=2.4.9" while 2.4.9 was an alpha). The final release already has the fix.
                $reported = substr((string) ($advisory['reportedAt'] ?? ''), 0, 10);
                if ($lineReleased !== '' && $reported !== '' && $reported < $lineReleased) {
                    continue;
                }
                $matches[$id] = $advisory;
            }
        }
        if (!$matches) {
            return [new Finding(
                'magento_version.advisories',
                Report::CATEGORY_PLATFORM,
                Severity::PASSED,
                (string) __('No known vulnerabilities for this version'),
                (string) __('None of the published Magento advisories on Packagist affect %1.', $version)
            )];
        }

        $worst = Severity::LOW;
        $lines = [];
        foreach ($matches as $id => $advisory) {
            $severity = $this->advisorySeverity((string) ($advisory['severity'] ?? ''));
            if ((Severity::RANK[$severity] ?? 9) < (Severity::RANK[$worst] ?? 9)) {
                $worst = $severity;
            }
            $lines[] = sprintf('%s (%s): %s', $id, $severity, (string) ($advisory['title'] ?? ''));
        }
        usort($lines, static fn (string $a, string $b): int => strcmp($a, $b));
        return [new Finding(
            'magento_version.advisories',
            Report::CATEGORY_PLATFORM,
            $worst,
            count($matches) === 1
                ? (string) __('A known vulnerability affects your Magento version')
                : (string) __('%1 known vulnerabilities affect your Magento version', count($matches)),
            (string) __('%1 is affected by: %2', $label, implode('; ', array_slice($lines, 0, 15))
                . (count($lines) > 15 ? ' …' : '')),
            (string) __('Install the latest security patch for your release line. Each advisory lists the '
                . 'version that fixes it.'),
            'https://packagist.org/packages/magento/community-edition/advisories'
        )];
    }

    /**
     * Map an advisory severity to ours (unknown counts as high).
     *
     * @param string $severity
     * @return string
     */
    private function advisorySeverity(string $severity): string
    {
        $severity = strtolower($severity);
        return in_array($severity, [Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW], true)
            ? $severity
            : Severity::HIGH;
    }

    /**
     * Finding for a lookup that failed.
     *
     * @param string $code
     * @param \Stringable|string $title
     * @return Finding
     */
    private function unavailable(string $code, \Stringable|string $title): Finding
    {
        return new Finding(
            $code,
            Report::CATEGORY_PLATFORM,
            Severity::INFO,
            (string) $title,
            (string) __('The public data source did not answer. The check tries again on its next run.')
        );
    }
}
