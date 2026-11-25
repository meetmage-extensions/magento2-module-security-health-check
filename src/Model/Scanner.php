<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

use Magento\Framework\FlagManager;
use Magento\Framework\Stdlib\DateTime\DateTime;
use MeetMage\SecurityHealthCheck\Model\Check\CheckInterface;
use MeetMage\SecurityHealthCheck\Model\Remote\JsonClient;
use Psr\Log\LoggerInterface;

/**
 * Runs every registered check and keeps the latest report (stored as a Magento flag, no extra tables).
 */
class Scanner
{
    public const FLAG_REPORT = 'meetmage_shc_report';
    public const FLAG_PREVIOUS = 'meetmage_shc_previous_report';

    /**
     * @var CheckInterface[]
     */
    private array $checks;

    /**
     * @var FlagManager
     */
    private FlagManager $flagManager;

    /**
     * @var DateTime
     */
    private DateTime $dateTime;

    /**
     * @var Config
     */
    private Config $config;

    /**
     * @var JsonClient
     */
    private JsonClient $client;

    /**
     * @var LoggerInterface
     */
    private LoggerInterface $logger;

    /**
     * @var ReportCodec
     */
    private ReportCodec $codec;

    /**
     * @param FlagManager $flagManager
     * @param DateTime $dateTime
     * @param Config $config
     * @param JsonClient $client
     * @param LoggerInterface $logger
     * @param ReportCodec $codec
     * @param CheckInterface[] $checks
     */
    public function __construct(
        FlagManager $flagManager,
        DateTime $dateTime,
        Config $config,
        JsonClient $client,
        LoggerInterface $logger,
        ReportCodec $codec,
        array $checks = []
    ) {
        $this->flagManager = $flagManager;
        $this->dateTime = $dateTime;
        $this->config = $config;
        $this->client = $client;
        $this->logger = $logger;
        $this->codec = $codec;
        $this->checks = array_filter($checks, static fn ($check): bool => $check instanceof CheckInterface);
    }

    /**
     * Run all checks, store the report and return it.
     *
     * @param bool $fresh Ignore cached public data
     * @return Report
     */
    public function scan(bool $fresh = false): Report
    {
        if ($fresh) {
            $this->client->clean();
        }
        $ignored = array_flip($this->config->getIgnoredChecks());
        $findings = [];
        foreach ($this->checks as $name => $check) {
            try {
                foreach ($check->run() as $finding) {
                    if ($finding instanceof Finding && !$this->isIgnored($finding->getCode(), $ignored)) {
                        $findings[] = $finding;
                    }
                }
            } catch (\Throwable $e) {
                $this->logger->error(sprintf('[SecurityHealthCheck] Check "%s" failed: %s', $name, $e->getMessage()));
                $findings[] = new Finding(
                    'check_error.' . $name,
                    Report::CATEGORY_CONFIG,
                    Severity::INFO,
                    (string) __('The "%1" check could not run', $name),
                    $e->getMessage()
                );
            }
        }

        $report = new Report($findings, $this->dateTime->gmtDate());
        $current = $this->flagManager->getFlagData(self::FLAG_REPORT);
        if (is_array($current)) {
            $this->flagManager->saveFlag(self::FLAG_PREVIOUS, $current);
        }
        $this->flagManager->saveFlag(self::FLAG_REPORT, $report->toArray());
        return $report;
    }

    /**
     * The latest stored report, if a check has run.
     *
     * @return Report|null
     */
    public function getLatest(): ?Report
    {
        return $this->load(self::FLAG_REPORT);
    }

    /**
     * The report before the latest one.
     *
     * @return Report|null
     */
    public function getPrevious(): ?Report
    {
        return $this->load(self::FLAG_PREVIOUS);
    }

    /**
     * Load a stored report.
     *
     * @param string $flag
     * @return Report|null
     */
    private function load(string $flag): ?Report
    {
        $data = $this->flagManager->getFlagData($flag);
        return is_array($data) ? $this->codec->toReport($data) : null;
    }

    /**
     * Whether a code matches an ignore entry (exact, or a prefix ending in "*").
     *
     * @param string $code
     * @param array<string,int> $ignored
     * @return bool
     */
    private function isIgnored(string $code, array $ignored): bool
    {
        if (isset($ignored[$code])) {
            return true;
        }
        foreach (array_keys($ignored) as $pattern) {
            if (str_ends_with($pattern, '*') && str_starts_with($code, substr($pattern, 0, -1))) {
                return true;
            }
        }
        return false;
    }
}
