<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\System\Message;

use Magento\Framework\AuthorizationInterface;
use Magento\Framework\Notification\MessageInterface;
use Magento\Framework\UrlInterface;
use MeetMage\SecurityHealthCheck\Model\Report;
use MeetMage\SecurityHealthCheck\Model\Scanner;
use MeetMage\SecurityHealthCheck\Model\Severity;

/**
 * Admin notice while critical or high issues are open.
 */
class SeriousIssues implements MessageInterface
{
    /**
     * @var Scanner
     */
    private Scanner $scanner;

    /**
     * @var UrlInterface
     */
    private UrlInterface $urlBuilder;

    /**
     * @var AuthorizationInterface
     */
    private AuthorizationInterface $authorization;

    /**
     * @var string[]|null
     */
    private ?array $codes = null;

    /**
     * @param Scanner $scanner
     * @param UrlInterface $urlBuilder
     * @param AuthorizationInterface $authorization
     */
    public function __construct(Scanner $scanner, UrlInterface $urlBuilder, AuthorizationInterface $authorization)
    {
        $this->scanner = $scanner;
        $this->urlBuilder = $urlBuilder;
        $this->authorization = $authorization;
    }

    /**
     * Changes with the set of issues, so a dismissed notice returns when a new issue appears.
     *
     * @return string
     */
    public function getIdentity(): string
    {
        return 'meetmage_shc_' . hash('sha256', implode(',', $this->getCodes()));
    }

    /**
     * Whether to show the notice.
     *
     * @return bool
     */
    public function isDisplayed(): bool
    {
        return $this->authorization->isAllowed('MeetMage_SecurityHealthCheck::report') && $this->getCodes() !== [];
    }

    /**
     * Notice text.
     *
     * @return string
     */
    public function getText(): string
    {
        return (string) __(
            'Security Health Check: %1 critical or high security issue(s) need attention. '
            . '<a href="%2">See how to fix them</a>.',
            count($this->getCodes()),
            $this->urlBuilder->getUrl('meetmage_shc/report/index')
        );
    }

    /**
     * Severity of the notice.
     *
     * @return int
     */
    public function getSeverity(): int
    {
        return self::SEVERITY_MAJOR;
    }

    /**
     * Codes of open critical and high issues.
     *
     * @return string[]
     */
    private function getCodes(): array
    {
        if ($this->codes === null) {
            try {
                $report = $this->scanner->getLatest();
                $this->codes = $report instanceof Report ? $report->issueCodes(Severity::HIGH) : [];
            } catch (\Exception $e) {
                $this->codes = [];
            }
        }
        return $this->codes;
    }
}
