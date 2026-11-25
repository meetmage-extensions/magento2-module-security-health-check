<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Check;

use Magento\Framework\Stdlib\DateTime\DateTime;
use MeetMage\SecurityHealthCheck\Model\Finding;
use MeetMage\SecurityHealthCheck\Model\Lifecycle;
use MeetMage\SecurityHealthCheck\Model\Remote\DataSources;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Severity;

/**
 * Does the PHP version still get security fixes?
 */
class PhpVersion implements CheckInterface
{
    private const INFO_URL = 'https://www.php.net/supported-versions.php';

    /**
     * @var DataSources
     */
    private DataSources $sources;

    /**
     * @var Lifecycle
     */
    private Lifecycle $lifecycle;

    /**
     * @var DateTime
     */
    private DateTime $dateTime;

    /**
     * @var string
     */
    private string $phpVersion;

    /**
     * @param DataSources $sources
     * @param Lifecycle $lifecycle
     * @param DateTime $dateTime
     * @param string $phpVersion Override for tests; defaults to the running PHP
     */
    public function __construct(
        DataSources $sources,
        Lifecycle $lifecycle,
        DateTime $dateTime,
        string $phpVersion = ''
    ) {
        $this->sources = $sources;
        $this->lifecycle = $lifecycle;
        $this->dateTime = $dateTime;
        $this->phpVersion = $phpVersion !== '' ? $phpVersion : PHP_VERSION;
    }

    /**
     * @inheritDoc
     */
    public function run(): array
    {
        $cycle = implode('.', array_slice(explode('.', $this->phpVersion), 0, 2));
        $cycles = $this->sources->getLifecycle('php');
        if ($cycles === null) {
            return [new Finding(
                'php_version.lifecycle',
                Report::CATEGORY_PLATFORM,
                Severity::INFO,
                (string) __('PHP %1 support dates not checked', $this->phpVersion),
                (string) __('External lookups are off or endoflife.date did not answer.')
            )];
        }
        $info = $this->lifecycle->evaluate($cycles, $cycle, $this->dateTime->gmtDate('Y-m-d'));
        $code = 'php_version.lifecycle';
        switch ($info['status']) {
            case Lifecycle::END_OF_LIFE:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::CRITICAL,
                    (string) __('PHP %1 is end of life', $cycle),
                    (string) __('PHP %1 stopped receiving security fixes on %2.', $this->phpVersion, $info['eol']),
                    (string) __('Move to a PHP version your Magento release supports and that still gets security '
                        . 'fixes. A Magento upgrade may be needed first.'),
                    self::INFO_URL
                )];
            case Lifecycle::ENDING_SOON:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::MEDIUM,
                    (string) __('PHP %1 security support ends soon', $cycle),
                    (string) __('PHP %1 gets security fixes until %2.', $cycle, $info['eol']),
                    (string) __('Plan the move to a newer PHP version supported by your Magento release.'),
                    self::INFO_URL
                )];
            case Lifecycle::SECURITY_ONLY:
            case Lifecycle::SUPPORTED:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::PASSED,
                    (string) __('PHP %1 gets security fixes', $cycle),
                    (string) __('Running PHP %1; security support until %2.', $this->phpVersion, $info['eol'])
                )];
            default:
                return [new Finding(
                    $code,
                    Report::CATEGORY_PLATFORM,
                    Severity::INFO,
                    (string) __('PHP %1 is not listed on endoflife.date', $cycle),
                    (string) __('Running PHP %1.', $this->phpVersion)
                )];
        }
    }
}
