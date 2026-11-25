<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Cron;

use MeetMage\SecurityHealthCheck\Model\Config;
use MeetMage\SecurityHealthCheck\Model\Notifier;
use MeetMage\SecurityHealthCheck\Model\Scanner;

/**
 * Daily health check, followed by the report email when one is due.
 */
class RunCheck
{
    /**
     * @var Config
     */
    private Config $config;

    /**
     * @var Scanner
     */
    private Scanner $scanner;

    /**
     * @var Notifier
     */
    private Notifier $notifier;

    /**
     * @param Config $config
     * @param Scanner $scanner
     * @param Notifier $notifier
     */
    public function __construct(Config $config, Scanner $scanner, Notifier $notifier)
    {
        $this->config = $config;
        $this->scanner = $scanner;
        $this->notifier = $notifier;
    }

    /**
     * Run the check.
     *
     * @return void
     */
    public function execute(): void
    {
        if (!$this->config->isEnabled()) {
            return;
        }
        $previous = $this->scanner->getLatest();
        $report = $this->scanner->scan();
        if ($this->notifier->isDue($report, $previous)) {
            $this->notifier->send($report);
        }
    }
}
