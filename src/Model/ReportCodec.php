<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

/**
 * Rebuilds a stored report (see Report::toArray()).
 */
class ReportCodec
{
    /**
     * Report from a stored array.
     *
     * @param array<string,mixed> $data
     * @return Report
     */
    public function toReport(array $data): Report
    {
        $findings = [];
        foreach ((array) ($data['findings'] ?? []) as $item) {
            if (is_array($item)) {
                $findings[] = $this->toFinding($item);
            }
        }
        return new Report($findings, (string) ($data['created_at'] ?? ''));
    }

    /**
     * Finding from a stored array.
     *
     * @param array<string,mixed> $data
     * @return Finding
     */
    public function toFinding(array $data): Finding
    {
        return new Finding(
            (string) ($data['code'] ?? ''),
            (string) ($data['category'] ?? ''),
            (string) ($data['severity'] ?? Severity::INFO),
            (string) ($data['title'] ?? ''),
            (string) ($data['detail'] ?? ''),
            (string) ($data['fix'] ?? ''),
            (string) ($data['link'] ?? '')
        );
    }
}
