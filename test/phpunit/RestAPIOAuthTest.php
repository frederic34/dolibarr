<?php
/* Copyright (C) 2026		Frédéric France			<frederic.france@free.fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * or see https://www.gnu.org/
 */

/**
 * \file    test/phpunit/RestAPIOAuthTest.php
 * \ingroup test
 * \brief   PHPUnit tests of the REST API with OAuth access tokens
 */

global $conf, $user, $langs, $db;
require_once dirname(__FILE__).'/../../htdocs/master.inc.php';
require_once dirname(__FILE__).'/../../htdocs/core/lib/admin.lib.php';
require_once dirname(__FILE__).'/../../htdocs/core/lib/geturl.lib.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthserverclient.class.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthservertoken.class.php';
require_once dirname(__FILE__).'/CommonClassTest.class.php';

if (empty($user->id)) {
	print "Load permissions for admin user nb 1\n";
	$user->fetch(1);
	$user->loadRights();
}
$conf->global->MAIN_DISABLE_ALL_MAILS = 1;


/**
 * Class for PHPUnit tests (set DOL_TEST_URL_ROOT, e.g. https://webserver, when DOL_MAIN_URL_ROOT is not reachable from where the tests run)
 *
 * @backupStaticAttributes disabled
 */
class RestAPIOAuthTest extends CommonClassTest
{
	/**
	 * @var int[] Clients to delete at the end
	 */
	private static $clientids = [];

	/**
	 * Enable the modules api and oauthserver when the database does not have them
	 *
	 * @return void
	 */
	public static function setUpBeforeClass(): void
	{
		global $db, $conf;

		// Activating a module runs its SQL scripts (CREATE TABLE), an implicit commit: do it before
		// the test transaction is opened. The modules stay enabled (same as DonTest).
		if (!isModEnabled('api')) {
			$result = activateModule('modApi');
			self::assertEmpty($result['errors'], 'Failed to activate module api: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}
		if (!isModEnabled('oauthserver')) {
			$result = activateModule('modOAuthServer');
			self::assertEmpty($result['errors'], 'Failed to activate module oauthserver: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}
		self::assertTrue(isModEnabled('api') && isModEnabled('oauthserver'), 'modules api and oauthserver must be enabled');

		parent::setUpBeforeClass();
	}

	/**
	 * Delete the clients created by the tests
	 *
	 * @return void
	 */
	public static function tearDownAfterClass(): void
	{
		global $db, $user;
		foreach (self::$clientids as $id) {
			$client = new OAuthServerClient($db);
			if ($client->fetch($id) > 0) {
				$client->delete($user, 1);
			}
		}
		$db->commit();
		$db->begin();
		parent::tearDownAfterClass();
	}

	/**
	 * Issue a committed grant for user 1
	 *
	 * @param	string[]	$scopes		Scopes
	 * @return	OAuthServerToken		Grant with its plain access token
	 */
	private function newGrant($scopes)
	{
		global $db, $user;
		$client = new OAuthServerClient($db);
		$client->label = 'PHPUnit API';
		$client->redirect_uris = ['https://app.example/cb'];
		$client->allowed_scopes = ['api', 'mcp', 'read', 'write', 'offline_access'];
		$this->assertGreaterThan(0, $client->create($user, 1));
		self::$clientids[] = $client->id;
		$grant = new OAuthServerToken($db);
		$this->assertGreaterThan(0, $grant->issue($user, $client->id, (int) $user->id, $scopes, 1));
		$db->commit();
		$db->begin();

		return $grant;
	}

	/**
	 * Call the REST API
	 *
	 * @param	string		$method		GET, POST, DELETE
	 * @param	string		$path		Path after /api/index.php/
	 * @param	string[]	$headers	Headers
	 * @param	string		$body		JSON body
	 * @return	array{code:int,json:mixed}	Answer
	 */
	private function api($method, $path, $headers, $body = '')
	{
		$root = getenv('DOL_TEST_URL_ROOT') ?: DOL_MAIN_URL_ROOT;
		if (getenv('DOL_TEST_URL_ROOT')) {
			$headers[] = 'Host: '.parse_url(DOL_MAIN_URL_ROOT, PHP_URL_HOST);
		}
		$result = getURLContent($root.'/api/index.php/'.$path, $method, $body, 0,
			array_merge(['Content-Type: application/json', 'Accept: application/json'], $headers), ['https', 'http'], 2);

		return ['code' => (int) $result['http_code'], 'json' => json_decode((string) $result['content'], true)];
	}

	/**
	 * A read token reads
	 *
	 * @return void
	 */
	public function testReadToken()
	{
		global $user;
		$grant = $this->newGrant(['api', 'read']);
		$answer = $this->api('GET', 'users/info', ['Authorization: Bearer '.$grant->access_token]);
		$this->assertSame(200, $answer['code'], json_encode($answer['json']));
		$this->assertSame($user->login, $answer['json']['login']);
	}

	/**
	 * A read token cannot write
	 *
	 * @return void
	 */
	public function testReadOnlyTokenCannotWrite()
	{
		$grant = $this->newGrant(['api', 'read']);
		$answer = $this->api('POST', 'thirdparties', ['Authorization: Bearer '.$grant->access_token], (string) json_encode(['name' => 'PHPUnit OAuth read-only']));
		$this->assertSame(403, $answer['code']);
		$this->assertStringContainsString('read-only', (string) json_encode($answer['json']));
	}

	/**
	 * A read token cannot write through the method override header or parameter
	 *
	 * @return void
	 */
	public function testReadOnlyTokenCannotOverrideMethod()
	{
		$grant = $this->newGrant(['api', 'read']);
		$headers = ['Authorization: Bearer '.$grant->access_token];
		$body = (string) json_encode(['name' => 'PHPUnit OAuth override '.dol_now()]);

		$answers = [
			$this->api('GET', 'thirdparties', array_merge($headers, ['X-HTTP-Method-Override: POST']), $body),
			$this->api('GET', 'thirdparties?http_method=POST', $headers, $body),
		];
		foreach ($answers as $answer) {
			if ($answer['code'] === 200 && is_int($answer['json']) && $answer['json'] > 0) {
				// Regression: the third party was created, do not leave it
				$this->api('DELETE', 'thirdparties/'.$answer['json'], ['Authorization: Bearer '.$this->newGrant(['api', 'read', 'write'])->access_token]);
			}
			$this->assertSame(403, $answer['code'], json_encode($answer['json']));
			$this->assertStringContainsString('read-only', (string) json_encode($answer['json']));
		}
	}

	/**
	 * A write token writes (user 1 needs the third party create and delete rights)
	 *
	 * @return void
	 */
	public function testWriteTokenCanWrite()
	{
		$grant = $this->newGrant(['api', 'read', 'write']);
		$headers = ['Authorization: Bearer '.$grant->access_token];
		$answer = $this->api('POST', 'thirdparties', $headers, (string) json_encode(['name' => 'PHPUnit OAuth write '.dol_now()]));
		$this->assertSame(200, $answer['code'], json_encode($answer['json']));
		$id = (int) $answer['json'];
		$this->assertGreaterThan(0, $id);
		$this->assertSame(200, $this->api('DELETE', 'thirdparties/'.$id, $headers)['code']);
	}

	/**
	 * A token for MCP only is refused by the REST API
	 *
	 * @return void
	 */
	public function testMcpTokenRefused()
	{
		$grant = $this->newGrant(['mcp', 'read']);
		$this->assertSame(403, $this->api('GET', 'users/info', ['Authorization: Bearer '.$grant->access_token])['code']);
	}

	/**
	 * Expired and revoked tokens
	 *
	 * @return void
	 */
	public function testExpiredAndRevokedTokens()
	{
		global $db, $user;
		$grant = $this->newGrant(['api', 'read']);
		$db->query("UPDATE ".$db->prefix()."oauth_token SET expire_at = '".$db->idate(dol_now() - 10)."' WHERE rowid = ".((int) $grant->id));
		$db->commit();
		$db->begin();
		$this->assertSame(401, $this->api('GET', 'users/info', ['Authorization: Bearer '.$grant->access_token])['code']);

		$grant2 = $this->newGrant(['api', 'read']);
		$grant2->revoke($user, '');
		$db->commit();
		$db->begin();
		$this->assertSame(401, $this->api('GET', 'users/info', ['Authorization: Bearer '.$grant2->access_token])['code']);
	}

	/**
	 * OAuth tokens are refused outside the Authorization header
	 *
	 * @return void
	 */
	public function testTokenOnlyInBearerHeader()
	{
		$grant = $this->newGrant(['api', 'read']);
		$this->assertSame(401, $this->api('GET', 'users/info?DOLAPIKEY='.$grant->access_token, [])['code']);
		$this->assertSame(401, $this->api('GET', 'users/info', ['DOLAPIKEY: '.$grant->access_token])['code']);
	}
}
