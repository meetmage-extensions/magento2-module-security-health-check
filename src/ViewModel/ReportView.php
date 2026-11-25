<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\ViewModel;

use Magento\Framework\Stdlib\DateTime\TimezoneInterface;
use Magento\Framework\UrlInterface;
use Magento\Framework\View\Element\Block\ArgumentInterface;
use MeetMage\SecurityHealthCheck\Model\Config;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Scanner;
use MeetMage\SecurityHealthCheck\Model\Severity;

/**
 * Data for the admin report page.
 */
class ReportView implements ArgumentInterface
{
    /**
     * @var Scanner
     */
    private Scanner $scanner;

    /**
     * @var Config
     */
    private Config $config;

    /**
     * @var UrlInterface
     */
    private UrlInterface $urlBuilder;

    /**
     * @var TimezoneInterface
     */
    private TimezoneInterface $timezone;

    /**
     * @var Report|null
     */
    private ?Report $report = null;

    /**
     * @var bool
     */
    private bool $loaded = false;

    /**
     * @param Scanner $scanner
     * @param Config $config
     * @param UrlInterface $urlBuilder
     * @param TimezoneInterface $timezone
     */
    public function __construct(
        Scanner $scanner,
        Config $config,
        UrlInterface $urlBuilder,
        TimezoneInterface $timezone
    ) {
        $this->scanner = $scanner;
        $this->config = $config;
        $this->urlBuilder = $urlBuilder;
        $this->timezone = $timezone;
    }

    /**
     * The latest report, or null before the first run.
     *
     * @return Report|null
     */
    public function getReport(): ?Report
    {
        if (!$this->loaded) {
            $this->report = $this->scanner->getLatest();
            $this->loaded = true;
        }
        return $this->report;
    }

    /**
     * Findings grouped by category, in display order.
     *
     * @param bool $issuesOnly
     * @return array<string,Finding[]>
     */
    public function getGroups(bool $issuesOnly): array
    {
        $report = $this->getReport();
        if (!$report) {
            return [];
        }
        $groups = array_fill_keys(array_keys($this->getCategoryLabels()), []);
        foreach ($report->getFindings() as $finding) {
            if ($issuesOnly !== $finding->isIssue()) {
                continue;
            }
            $groups[$finding->getCategory()][] = $finding;
        }
        return array_filter($groups);
    }

    /**
     * Category labels.
     *
     * @return array<string,string>
     */
    public function getCategoryLabels(): array
    {
        return [
            Report::CATEGORY_PLATFORM => (string) __('Magento and PHP versions'),
            Report::CATEGORY_PACKAGES => (string) __('Extensions and libraries'),
            Report::CATEGORY_ADMIN => (string) __('Admin access'),
            Report::CATEGORY_CONFIG => (string) __('Store configuration'),
        ];
    }

    /**
     * Label for a category code.
     *
     * @param string $category
     * @return string
     */
    public function getCategoryLabel(string $category): string
    {
        return $this->getCategoryLabels()[$category] ?? ucfirst($category);
    }

    /**
     * Severity label.
     *
     * @param string $severity
     * @return string
     */
    public function getSeverityLabel(string $severity): string
    {
        $labels = [
            Severity::CRITICAL => __('Critical'),
            Severity::HIGH => __('High'),
            Severity::MEDIUM => __('Medium'),
            Severity::LOW => __('Low'),
            Severity::PASSED => __('Passed'),
            Severity::INFO => __('Info'),
        ];
        return (string) ($labels[$severity] ?? $severity);
    }

    /**
     * Score colour class.
     *
     * @param int $score
     * @return string
     */
    public function getScoreClass(int $score): string
    {
        if ($score >= 90) {
            return 'good';
        }
        return $score >= 70 ? 'fair' : 'poor';
    }

    /**
     * Report time in the admin's timezone.
     *
     * @param string $utc
     * @return string
     */
    public function formatTime(string $utc): string
    {
        if ($utc === '') {
            return '';
        }
        try {
            return $this->timezone->formatDateTime(
                new \DateTime($utc, new \DateTimeZone('UTC')),
                \IntlDateFormatter::MEDIUM,
                \IntlDateFormatter::SHORT
            );
        } catch (\Exception $e) {
            return $utc . ' UTC';
        }
    }

    /**
     * URL of the "Run check now" action.
     *
     * @return string
     */
    public function getRunUrl(): string
    {
        return $this->urlBuilder->getUrl('meetmage_shc/report/run');
    }

    /**
     * URL of the settings page.
     *
     * @return string
     */
    public function getSettingsUrl(): string
    {
        return $this->urlBuilder->getUrl('adminhtml/system_config/edit', ['section' => 'meetmage_securityhealthcheck']);
    }

    /**
     * Whether public lookups are on.
     *
     * @return bool
     */
    public function isExternalLookupAllowed(): bool
    {
        return $this->config->isExternalLookupAllowed();
    }
}
