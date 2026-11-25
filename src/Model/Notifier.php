<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

use Magento\Backend\Model\UrlInterface as BackendUrl;
use Magento\Framework\App\Area;
use Magento\Framework\Escaper;
use Magento\Framework\FlagManager;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Magento\Store\Model\Store;
use Magento\Store\Model\StoreManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Emails the health report: on new issues, weekly or daily (see configuration).
 */
class Notifier
{
    private const FLAG_LAST_SENT = 'meetmage_shc_last_email';

    /**
     * @var Config
     */
    private Config $config;

    /**
     * @var TransportBuilder
     */
    private TransportBuilder $transportBuilder;

    /**
     * @var Escaper
     */
    private Escaper $escaper;

    /**
     * @var BackendUrl
     */
    private BackendUrl $backendUrl;

    /**
     * @var FlagManager
     */
    private FlagManager $flagManager;

    /**
     * @var DateTime
     */
    private DateTime $dateTime;

    /**
     * @var StoreManagerInterface
     */
    private StoreManagerInterface $storeManager;

    /**
     * @var LoggerInterface
     */
    private LoggerInterface $logger;

    /**
     * @param Config $config
     * @param TransportBuilder $transportBuilder
     * @param Escaper $escaper
     * @param BackendUrl $backendUrl
     * @param FlagManager $flagManager
     * @param DateTime $dateTime
     * @param StoreManagerInterface $storeManager
     * @param LoggerInterface $logger
     */
    public function __construct(
        Config $config,
        TransportBuilder $transportBuilder,
        Escaper $escaper,
        BackendUrl $backendUrl,
        FlagManager $flagManager,
        DateTime $dateTime,
        StoreManagerInterface $storeManager,
        LoggerInterface $logger
    ) {
        $this->config = $config;
        $this->transportBuilder = $transportBuilder;
        $this->escaper = $escaper;
        $this->backendUrl = $backendUrl;
        $this->flagManager = $flagManager;
        $this->dateTime = $dateTime;
        $this->storeManager = $storeManager;
        $this->logger = $logger;
    }

    /**
     * Whether a report email is due.
     *
     * @param Report $report
     * @param Report|null $previous
     * @return bool
     */
    public function isDue(Report $report, ?Report $previous): bool
    {
        if (!$this->config->isEmailEnabled() || !$this->config->getEmailRecipients()) {
            return false;
        }
        $newIssues = array_diff($report->issueCodes(Severity::MEDIUM), $previous ? $previous->issueCodes() : []);
        if ($newIssues) {
            return true; // always tell about new medium-or-worse issues
        }
        if (!$report->getIssues()) {
            return false;
        }
        $lastSent = (int) $this->flagManager->getFlagData(self::FLAG_LAST_SENT);
        $elapsed = (int) $this->dateTime->gmtTimestamp() - $lastSent;
        switch ($this->config->getEmailFrequency()) {
            case Config::FREQUENCY_DAILY:
                return $elapsed >= 82800; // 23 hours, so a daily cron always qualifies
            case Config::FREQUENCY_WEEKLY:
                return $elapsed >= 601200; // 7 days minus 1 hour
            default:
                return false;
        }
    }

    /**
     * Send the report to the configured recipients.
     *
     * @param Report $report
     * @return bool True when the email went out
     */
    public function send(Report $report): bool
    {
        $recipients = $this->config->getEmailRecipients();
        if (!$recipients) {
            return false;
        }
        $counts = $report->countBySeverity();
        $issues = count($report->getIssues());
        try {
            $this->transportBuilder
                ->setTemplateIdentifier($this->config->getEmailTemplate())
                ->setTemplateOptions(['area' => Area::AREA_ADMINHTML, 'store' => Store::DEFAULT_STORE_ID])
                ->setTemplateVars([
                    'store_url' => $this->getStoreUrl(),
                    'score' => $report->getScore(),
                    'issues' => $issues,
                    'critical' => $counts[Severity::CRITICAL],
                    'high' => $counts[Severity::HIGH],
                    'subject_prefix' => $counts[Severity::CRITICAL] ? 'CRITICAL: ' : '',
                    'findings_html' => $this->renderFindings($report),
                    'report_url' => $this->backendUrl->getUrl('meetmage_shc/report/index', ['_nosecret' => true]),
                ])
                ->setFromByScope($this->config->getEmailIdentity(), Store::DEFAULT_STORE_ID);
            foreach ($recipients as $email) {
                $this->transportBuilder->addTo($email);
            }
            $this->transportBuilder->getTransport()->sendMessage();
        } catch (\Exception $e) {
            $this->logger->error('[SecurityHealthCheck] Could not send the report email: ' . $e->getMessage());
            return false;
        }
        $this->flagManager->saveFlag(self::FLAG_LAST_SENT, (int) $this->dateTime->gmtTimestamp());
        return true;
    }

    /**
     * HTML table of issues for the email.
     *
     * @param Report $report
     * @return string
     */
    private function renderFindings(Report $report): string
    {
        $colors = [
            Severity::CRITICAL => '#b91c1c',
            Severity::HIGH => '#c2410c',
            Severity::MEDIUM => '#b45309',
            Severity::LOW => '#4b5563',
        ];
        $rows = '';
        foreach ($report->getIssues() as $finding) {
            $rows .= sprintf(
                '<tr><td style="padding:8px;border-bottom:1px solid #e5e7eb;vertical-align:top;white-space:nowrap;'
                . 'color:%s;font-weight:bold">%s</td><td style="padding:8px;border-bottom:1px solid #e5e7eb">'
                . '<strong>%s</strong><br><span style="color:#4b5563">%s</span></td></tr>',
                $colors[$finding->getSeverity()] ?? '#374151',
                $this->escaper->escapeHtml(strtoupper($finding->getSeverity())),
                $this->escaper->escapeHtml($finding->getTitle()),
                $this->escaper->escapeHtml($finding->getFix() ?: $finding->getDetail())
            );
        }
        if ($rows === '') {
            return '<p>' . $this->escaper->escapeHtml((string) __('No issues found. Nice work!')) . '</p>';
        }
        return '<table style="border-collapse:collapse;width:100%;font-size:13px">' . $rows . '</table>';
    }

    /**
     * Base URL of the default store, to say which store the email is about.
     *
     * @return string
     */
    private function getStoreUrl(): string
    {
        try {
            return (string) $this->storeManager->getDefaultStoreView()?->getBaseUrl();
        } catch (\Exception $e) {
            return '';
        }
    }
}
