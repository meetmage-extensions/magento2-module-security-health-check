<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

/**
 * The result of one full health check: all findings plus a 0-100 score.
 */
class Report
{
    public const CATEGORY_PLATFORM = 'platform';
    public const CATEGORY_PACKAGES = 'packages';
    public const CATEGORY_ADMIN = 'admin';
    public const CATEGORY_CONFIG = 'config';

    /**
     * @var Finding[]
     */
    private array $findings;

    /**
     * @var string
     */
    private string $createdAt;

    /**
     * @param Finding[] $findings
     * @param string $createdAt UTC date and time (Y-m-d H:i:s)
     */
    public function __construct(array $findings, string $createdAt)
    {
        usort(
            $findings,
            static fn (Finding $a, Finding $b): int =>
                [(Severity::RANK[$a->getSeverity()] ?? 9), $a->getCategory(), $a->getCode()]
                <=> [(Severity::RANK[$b->getSeverity()] ?? 9), $b->getCategory(), $b->getCode()]
        );
        $this->findings = $findings;
        $this->createdAt = $createdAt;
    }

    /**
     * All findings, most serious first.
     *
     * @return Finding[]
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Findings that need fixing.
     *
     * @return Finding[]
     */
    public function getIssues(): array
    {
        return array_values(array_filter($this->findings, static fn (Finding $f): bool => $f->isIssue()));
    }

    /**
     * When the check ran (UTC).
     *
     * @return string
     */
    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    /**
     * Health score from 0 to 100.
     *
     * @return int
     */
    public function getScore(): int
    {
        $penalty = 0;
        foreach ($this->findings as $finding) {
            $penalty += (Severity::PENALTY[$finding->getSeverity()] ?? 0);
        }
        return max(0, 100 - $penalty);
    }

    /**
     * Number of findings per severity.
     *
     * @return array<string,int>
     */
    public function countBySeverity(): array
    {
        $counts = [
            Severity::CRITICAL => 0,
            Severity::HIGH => 0,
            Severity::MEDIUM => 0,
            Severity::LOW => 0,
            Severity::PASSED => 0,
            Severity::INFO => 0,
        ];
        foreach ($this->findings as $finding) {
            $counts[$finding->getSeverity()]++;
        }
        return $counts;
    }

    /**
     * Codes of current issues at or above the given severity.
     *
     * @param string $minimum
     * @return string[]
     */
    public function issueCodes(string $minimum = Severity::LOW): array
    {
        $limit = (Severity::RANK[$minimum] ?? 9);
        $codes = [];
        foreach ($this->getIssues() as $finding) {
            if ((Severity::RANK[$finding->getSeverity()] ?? 9) <= $limit) {
                $codes[] = $finding->getCode();
            }
        }
        return $codes;
    }

    /**
     * Plain array for storage.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'created_at' => $this->createdAt,
            'findings' => array_map(static fn (Finding $f): array => $f->toArray(), $this->findings),
        ];
    }
}
