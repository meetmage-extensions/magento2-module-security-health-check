<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model;

/**
 * Reads endoflife.date release cycles and says where a version stands.
 */
class Lifecycle
{
    public const SUPPORTED = 'supported';
    public const ENDING_SOON = 'ending_soon';
    public const SECURITY_ONLY = 'security_only';
    public const EXTENDED = 'extended';
    public const END_OF_LIFE = 'eol';
    public const UNKNOWN = 'unknown';

    private const SOON_DAYS = 180;

    /**
     * Status of a release cycle on a given day.
     *
     * @param array<int,array<string,mixed>> $cycles endoflife.date data
     * @param string $cycle e.g. "2.4.8" or "8.3"
     * @param string $today Y-m-d
     * @return array{status:string,eol:string,support:string,extended:string}
     */
    public function evaluate(array $cycles, string $cycle, string $today): array
    {
        $row = null;
        foreach ($cycles as $item) {
            if ((string) ($item['cycle'] ?? '') === $cycle) {
                $row = $item;
                break;
            }
        }
        $result = ['status' => self::UNKNOWN, 'eol' => '', 'support' => '', 'extended' => ''];
        if ($row === null) {
            return $result;
        }
        $eol = $this->date($row['eol'] ?? null);
        $support = $this->date($row['support'] ?? null);
        $extended = $this->date($row['extendedSupport'] ?? null);
        $result['eol'] = $eol;
        $result['support'] = $support;
        $result['extended'] = $extended;

        if ($eol !== '' && $eol <= $today) {
            $result['status'] = ($extended !== '' && $extended > $today) ? self::EXTENDED : self::END_OF_LIFE;
            return $result;
        }
        $end = $eol !== '' ? $eol : $extended;
        if ($end !== '' && $this->daysBetween($today, $end) <= self::SOON_DAYS) {
            $result['status'] = self::ENDING_SOON;
            return $result;
        }
        if ($support !== '' && $support <= $today) {
            $result['status'] = self::SECURITY_ONLY;
            return $result;
        }
        $result['status'] = self::SUPPORTED;
        return $result;
    }

    /**
     * Newest cycle listed (first entry on endoflife.date).
     *
     * @param array<int,array<string,mixed>> $cycles
     * @return string
     */
    public function newestCycle(array $cycles): string
    {
        $newest = '';
        foreach ($cycles as $item) {
            $cycle = (string) ($item['cycle'] ?? '');
            if ($cycle !== '' && ($newest === '' || version_compare($cycle, $newest, '>'))) {
                $newest = $cycle;
            }
        }
        return $newest;
    }

    /**
     * A Y-m-d date from an endoflife.date field (false/true/null mean "no date").
     *
     * @param mixed $value
     * @return string
     */
    private function date(mixed $value): string
    {
        return is_string($value) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) ? $value : '';
    }

    /**
     * Whole days from $from to $to.
     *
     * @param string $from
     * @param string $to
     * @return int
     */
    private function daysBetween(string $from, string $to): int
    {
        return (int) floor((strtotime($to . ' 00:00:00 UTC') - strtotime($from . ' 00:00:00 UTC')) / 86400);
    }
}
