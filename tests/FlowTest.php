<?php

namespace Io\Auth\Tests;

use PHPUnit\Framework\TestCase;

/** Fixtures/flow.php under a real Tenma, on a database of its own. Skipped without tenma (TENMA_BIN) or Postgres (PG_BIN). */
final class FlowTest extends TestCase
{
    private const string DATABASE = 'io_auth_flow_test';

    public function testEveryServiceAgainstPostgres(): void
    {
        $tenma = getenv('TENMA_BIN') ?: trim((string) shell_exec('command -v tenma'));
        $pg = getenv('PG_BIN') ?: '/opt/homebrew/opt/libpq/bin';
        if ($tenma === '' || !is_executable($tenma) || !is_executable("$pg/createdb")) {
            $this->markTestSkipped('Needs tenma and the Postgres tools (TENMA_BIN, PG_BIN)');
        }
        exec(escapeshellarg("$pg/dropdb") . ' -h localhost --force --if-exists ' . self::DATABASE . ' 2>&1');
        exec(escapeshellarg("$pg/createdb") . ' -h localhost ' . self::DATABASE . ' 2>&1', $output, $status);
        if ($status !== 0) {
            $this->markTestSkipped('No Postgres on localhost: ' . implode(' ', $output));
        }
        $url = 'postgres://' . (getenv('USER') ?: 'postgres') . '@localhost/' . self::DATABASE;

        $result = shell_exec('DATABASE_URL=' . escapeshellarg($url) . ' ' . escapeshellarg($tenma) . ' ' . escapeshellarg(__DIR__ . '/Fixtures/flow.php') . ' 2>&1');

        $this->assertSame("ok\n", $result);
    }
}
