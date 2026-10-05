<?php
declare(strict_types=1);

namespace App\Security;

/** Anything that can deliver one event and report how it went. SecurityClient is the real one. */
interface EventSender
{
    /** @return array{result:string,status:int} result is "sent", "rejected" or "failed" */
    public function sendEvent(array $payload): array;
}
