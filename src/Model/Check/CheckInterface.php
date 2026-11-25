<?php
declare(strict_types=1);

namespace MeetMage\SecurityHealthCheck\Model\Check;

use MeetMage\SecurityHealthCheck\Model\Finding;

/**
 * A group of related security checks. Add your own through di.xml (Scanner "checks" argument).
 */
interface CheckInterface
{
    /**
     * Run the checks and return their findings (passed checks included).
     *
     * @return Finding[]
     */
    public function run(): array;
}
