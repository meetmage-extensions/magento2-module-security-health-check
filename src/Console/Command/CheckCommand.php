<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Console\Command;

use Magento\Framework\App\Area;
use Magento\Framework\App\State;
use MeetMage\SecurityHealthCheck\Model\Notifier;
use MeetMage\SecurityHealthCheck\Model\Scanner;
use MeetMage\SecurityHealthCheck\Model\Severity;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * bin/magento meetmage:security:check [--all] [--email] [--fail-on=high]
 */
class CheckCommand extends Command
{
    private const OPTION_ALL = 'all';
    private const OPTION_EMAIL = 'email';
    private const OPTION_FAIL_ON = 'fail-on';

    /**
     * @var Scanner
     */
    private Scanner $scanner;

    /**
     * @var Notifier
     */
    private Notifier $notifier;

    /**
     * @var State
     */
    private State $appState;

    /**
     * @param Scanner $scanner
     * @param Notifier $notifier
     * @param State $appState
     * @param string|null $name
     */
    public function __construct(Scanner $scanner, Notifier $notifier, State $appState, ?string $name = null)
    {
        $this->scanner = $scanner;
        $this->notifier = $notifier;
        $this->appState = $appState;
        parent::__construct($name);
    }

    /**
     * @inheritDoc
     */
    protected function configure(): void
    {
        $this->setName('meetmage:security:check')
            ->setDescription('Run the MeetMage Security Health Check and print the findings')
            ->addOption(self::OPTION_ALL, null, InputOption::VALUE_NONE, 'Also list passed checks')
            ->addOption(
                self::OPTION_EMAIL,
                null,
                InputOption::VALUE_NONE,
                'Email the report to the configured recipients'
            )
            ->addOption(
                self::OPTION_FAIL_ON,
                null,
                InputOption::VALUE_REQUIRED,
                'Exit with code 1 when an issue of this severity or worse is found (critical, high, medium, low)'
            );
        parent::configure();
    }

    /**
     * @inheritDoc
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $this->appState->setAreaCode(Area::AREA_ADMINHTML);
        } catch (\Exception $e) {
            // Area already set.
            $output->writeln('', OutputInterface::VERBOSITY_DEBUG);
        }

        $report = $this->scanner->scan(true);
        $showAll = (bool) $input->getOption(self::OPTION_ALL);
        $rows = [];
        foreach ($report->getFindings() as $finding) {
            if (!$showAll && !$finding->isIssue()) {
                continue;
            }
            $rows[] = [
                strtoupper($finding->getSeverity()),
                $finding->getTitle(),
                wordwrap($finding->getFix() ?: $finding->getDetail(), 70, "\n", true),
            ];
        }

        $output->writeln(sprintf('<info>Security health score: %d/100</info>', $report->getScore()));
        if ($rows) {
            $table = new Table($output);
            $table->setHeaders(['Severity', 'Finding', 'How to fix']);
            $table->setRows($rows);
            $table->render();
        } else {
            $output->writeln('No issues found.');
        }

        if ($input->getOption(self::OPTION_EMAIL)) {
            $output->writeln($this->notifier->send($report)
                ? 'Report emailed.'
                : '<comment>Report not emailed: check the recipients and the log.</comment>');
        }

        $failOn = strtolower((string) $input->getOption(self::OPTION_FAIL_ON));
        if (isset(Severity::PENALTY[$failOn]) && $report->issueCodes($failOn)) {
            return Command::FAILURE;
        }
        return Command::SUCCESS;
    }
}
