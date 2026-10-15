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
 * \file    test/phpunit/OAuthServerHttpTest.php
 * \ingroup test
 * \brief   PHPUnit tests of the OAuth Server endpoints, through HTTP
 */

global $conf, $user, $langs, $db;
require_once dirname(__FILE__).'/../../htdocs/master.inc.php';
require_once dirname(__FILE__).'/../../htdocs/core/lib/admin.lib.php';
require_once dirname(__FILE__).'/../../htdocs/core/lib/geturl.lib.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/lib/oauthserver.lib.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthserverclient.class.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthserverauthcode.class.php';
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
class OAuthServerHttpTest extends CommonClassTest
{
	/**
	 * @var int[] Clients to delete at the end
	 */
	private static $clientids = [];

	/**
	 * @var string[] Constants set for the tests, removed at the end
	 */
	private static $constsset = [];

	const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
	const REDIRECT = 'https://app.example/cb';

	/**
	 * Enable the module and the settings the endpoints need, committed so that the web server sees them
	 *
	 * @return void
	 */
	public static function setUpBeforeClass(): void
	{
		global $db, $conf;

		if (!isModEnabled('oauthserver')) {
			// Activating a module runs its SQL scripts (CREATE TABLE), an implicit commit: do it
			// before the test transaction is opened. The module stays enabled (same as DonTest).
			$result = activateModule('modOAuthServer');
			self::assertEmpty($result['errors'], 'Failed to activate module oauthserver: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}
		self::assertTrue(isModEnabled('oauthserver'), 'module oauthserver must be enabled');

		// The endpoints refuse plain HTTP: allow it while the tests run against an http:// instance (CI)
		if (strpos(self::urlRoot(), 'http://') === 0) {
			self::setTestConst('OAUTHSERVER_ALLOW_HTTP');
		}

		parent::setUpBeforeClass();
	}

	/**
	 * Delete the clients created by the tests (their codes and grants go with them), then the constants
	 *
	 * @return void
	 */
	public static function tearDownAfterClass(): void
	{
		global $db, $conf, $user;
		foreach (self::$clientids as $id) {
			$client = new OAuthServerClient($db);
			if ($client->fetch($id) > 0) {
				$client->delete($user, 1);
			}
		}
		$db->commit();
		$db->begin();
		parent::tearDownAfterClass();

		foreach (self::$constsset as $name) {
			dolibarr_del_const($db, $name, $conf->entity);
		}
		self::$constsset = [];
	}

	/**
	 * Set a constant to 1, outside of the test transaction, unless it is already set
	 *
	 * @param	string	$name	Constant
	 * @return	void
	 */
	private static function setTestConst($name)
	{
		global $db, $conf;
		if (!getDolGlobalString($name)) {
			dolibarr_set_const($db, $name, '1', 'chaine', 0, '', $conf->entity);
			self::$constsset[] = $name;
		}
	}

	/**
	 * Root URL the requests are sent to
	 *
	 * @return string URL
	 */
	private static function urlRoot()
	{
		return getenv('DOL_TEST_URL_ROOT') ?: DOL_MAIN_URL_ROOT;
	}

	/**
	 * Make the fixtures visible to the web server and see what it wrote
	 *
	 * @return void
	 */
	private function commitAndRestart()
	{
		global $db;
		$db->commit();
		$db->begin();
	}

	/**
	 * Create a committed client
	 *
	 * @param	string	$method		token_endpoint_auth_method
	 * @return	OAuthServerClient	Client, with client_secret_plain for a confidential one
	 */
	private function newClient($method = 'none')
	{
		global $db, $user;
		$client = new OAuthServerClient($db);
		$client->label = 'PHPUnit HTTP '.$method;
		$client->redirect_uris = [self::REDIRECT];
		$client->allowed_scopes = ['api', 'mcp', 'read', 'write', 'offline_access'];
		$client->token_endpoint_auth_method = $method;
		$this->assertGreaterThan(0, $client->create($user, 1));
		self::$clientids[] = $client->id;
		$this->commitAndRestart();

		return $client;
	}

	/**
	 * Create a committed authorization code, as authorize.php would
	 *
	 * @param	OAuthServerClient	$client		Client
	 * @param	string[]			$scopes		Scopes
	 * @return	string							Plain code
	 */
	private function newCode($client, $scopes = ['mcp', 'offline_access', 'read'])
	{
		global $db, $user;
		$code = new OAuthServerAuthCode($db);
		$code->entity = 1;
		$code->fk_oauth_client = (int) $client->id;
		$code->fk_user = (int) $user->id;
		$code->redirect_uri = self::REDIRECT;
		$code->scopes = $scopes;
		$code->code_challenge = oauthserverBase64UrlEncode(hash('sha256', self::VERIFIER, true));
		$plain = $code->create();
		$this->assertNotSame('', $plain);
		$this->commitAndRestart();

		return $plain;
	}

	/**
	 * Build the URL of an endpoint
	 *
	 * @param	string	$script		Script in htdocs/oauthserver
	 * @return	string				URL
	 */
	private function requestUrl($script)
	{
		return self::urlRoot().'/oauthserver/'.$script;
	}

	/**
	 * Build the headers of a request (Host header when the root is overridden)
	 *
	 * @param	string[]	$headers	Extra headers
	 * @return	string[]				Headers
	 */
	private function requestHeaders($headers = [])
	{
		if (getenv('DOL_TEST_URL_ROOT')) {
			$headers[] = 'Host: '.parse_url(DOL_MAIN_URL_ROOT, PHP_URL_HOST);
		}

		return $headers;
	}

	/**
	 * POST to an endpoint
	 *
	 * @param	string					$script		Script in htdocs/oauthserver
	 * @param	array<string,string>	$params		Form fields
	 * @param	string[]				$headers	Extra headers
	 * @return	array{code:int,json:mixed}		HTTP status and decoded body
	 */
	private function post($script, $params, $headers = [])
	{
		$result = getURLContent($this->requestUrl($script), 'POST', http_build_query($params), 0,
			$this->requestHeaders(array_merge(['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'], $headers)), ['https', 'http'], 2);

		return ['code' => (int) $result['http_code'], 'json' => json_decode((string) $result['content'], true)];
	}

	/**
	 * Exchange a code with the right verifier
	 *
	 * @param	OAuthServerClient	$client		Client
	 * @param	string				$code		Code
	 * @return	array{code:int,json:mixed}	Answer
	 */
	private function exchange($client, $code)
	{
		return $this->post('token.php', ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => self::REDIRECT,
			'code_verifier' => self::VERIFIER, 'client_id' => $client->client_id]);
	}

	/**
	 * Metadata document
	 *
	 * @return void
	 */
	public function testMetadata()
	{
		$result = getURLContent($this->requestUrl('metadata.php'), 'GET', '', 0, $this->requestHeaders(), ['https', 'http'], 2);
		$this->assertSame(200, (int) $result['http_code']);
		$json = json_decode((string) $result['content'], true);
		$this->assertSame(oauthserverGetIssuer(), $json['issuer']);
		$this->assertSame(['S256'], $json['code_challenge_methods_supported']);
		$this->assertSame(oauthserverGetIssuer().'/token.php', $json['token_endpoint']);
	}

	/**
	 * Full code exchange for a public client
	 *
	 * @return void
	 */
	public function testAuthorizationCodeFlow()
	{
		global $db;
		$client = $this->newClient();
		$answer = $this->exchange($client, $this->newCode($client));

		$this->assertSame(200, $answer['code'], json_encode($answer['json']));
		$this->assertSame('Bearer', $answer['json']['token_type']);
		$this->assertSame('mcp offline_access read', $answer['json']['scope']);
		$this->assertSame(1, preg_match('/^dolat_/', $answer['json']['access_token']));
		$this->assertSame(1, preg_match('/^dolrt_/', $answer['json']['refresh_token']));

		$this->commitAndRestart();
		$v = new OAuthServerToken($db);
		$this->assertSame(1, $v->validateAccessToken($answer['json']['access_token'], 'mcp'));
	}

	/**
	 * A code used twice: the second use fails and revokes the grant of the first
	 *
	 * @return void
	 */
	public function testCodeReplayRevokesGrant()
	{
		global $db;
		$client = $this->newClient();
		$code = $this->newCode($client);
		$first = $this->exchange($client, $code);
		$this->assertSame(200, $first['code']);
		$second = $this->exchange($client, $code);
		$this->assertSame(400, $second['code']);
		$this->assertSame('invalid_grant', $second['json']['error']);

		$this->commitAndRestart();
		$v = new OAuthServerToken($db);
		$this->assertSame(-1, $v->validateAccessToken($first['json']['access_token'], 'mcp'));
	}

	/**
	 * Wrong PKCE verifier, wrong redirect URI, other client
	 *
	 * @return void
	 */
	public function testCodeMismatches()
	{
		$client = $this->newClient();
		$other = $this->newClient();

		$answer = $this->post('token.php', ['grant_type' => 'authorization_code', 'code' => $this->newCode($client), 'redirect_uri' => self::REDIRECT,
			'code_verifier' => str_repeat('a', 43), 'client_id' => $client->client_id]);
		$this->assertSame('invalid_grant', $answer['json']['error']);

		$answer = $this->post('token.php', ['grant_type' => 'authorization_code', 'code' => $this->newCode($client), 'redirect_uri' => 'https://app.example/other',
			'code_verifier' => self::VERIFIER, 'client_id' => $client->client_id]);
		$this->assertSame('invalid_grant', $answer['json']['error']);

		$answer = $this->exchange($other, $this->newCode($client));
		$this->assertSame('invalid_grant', $answer['json']['error']);
	}

	/**
	 * Confidential client with the Basic header
	 *
	 * @return void
	 */
	public function testConfidentialClientBasic()
	{
		$client = $this->newClient('client_secret_basic');
		$params = ['grant_type' => 'authorization_code', 'code' => $this->newCode($client), 'redirect_uri' => self::REDIRECT, 'code_verifier' => self::VERIFIER];

		$bad = $this->post('token.php', $params, ['Authorization: Basic '.base64_encode($client->client_id.':dolcs_wrong')]);
		$this->assertSame(401, $bad['code']);
		$this->assertSame('invalid_client', $bad['json']['error']);

		$good = $this->post('token.php', $params, ['Authorization: Basic '.base64_encode($client->client_id.':'.$client->client_secret_plain)]);
		$this->assertSame(200, $good['code'], json_encode($good['json']));
	}

	/**
	 * Refresh rotation; the replaced token inside the grace period fails without revoking
	 *
	 * @return void
	 */
	public function testRefreshRotationAndGrace()
	{
		global $db;
		$client = $this->newClient();
		$tokens = $this->exchange($client, $this->newCode($client))['json'];

		$refresh = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token'], 'client_id' => $client->client_id, 'scope' => 'mcp read']);
		$this->assertSame(200, $refresh['code'], json_encode($refresh['json']));
		$this->assertNotSame($tokens['refresh_token'], $refresh['json']['refresh_token']);
		$this->assertSame('mcp offline_access read', $refresh['json']['scope']);

		$again = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token'], 'client_id' => $client->client_id]);
		$this->assertSame('invalid_grant', $again['json']['error']);

		$this->commitAndRestart();
		$v = new OAuthServerToken($db);
		$this->assertSame(1, $v->validateAccessToken($refresh['json']['access_token'], 'mcp'), 'a reuse inside the grace period does not revoke');

		$widen = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $refresh['json']['refresh_token'], 'client_id' => $client->client_id, 'scope' => 'mcp read write']);
		$this->assertSame('invalid_scope', $widen['json']['error']);
	}

	/**
	 * A refresh only keeps the scopes the client is still allowed
	 *
	 * @return void
	 */
	public function testRefreshHonoursClientScopes()
	{
		global $user;
		$client = $this->newClient();
		$tokens = $this->exchange($client, $this->newCode($client, ['mcp', 'offline_access', 'read', 'write']))['json'];
		$this->assertSame('mcp offline_access read write', $tokens['scope']);

		$client->allowed_scopes = ['mcp', 'read', 'offline_access'];
		$this->assertSame(1, $client->update($user));
		$this->commitAndRestart();
		$refresh = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $tokens['refresh_token'], 'client_id' => $client->client_id]);
		$this->assertSame(200, $refresh['code'], json_encode($refresh['json']));
		$this->assertSame('mcp offline_access read', $refresh['json']['scope'], 'write was withdrawn from the client');

		$client->allowed_scopes = ['api', 'read', 'offline_access'];
		$this->assertSame(1, $client->update($user));
		$this->commitAndRestart();
		$answer = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $refresh['json']['refresh_token'], 'client_id' => $client->client_id]);
		$this->assertSame(400, $answer['code']);
		$this->assertSame('invalid_scope', $answer['json']['error'], 'mcp was withdrawn from the client');

		$client->allowed_scopes = ['mcp', 'read'];
		$this->assertSame(1, $client->update($user));
		$this->commitAndRestart();
		$answer = $this->post('token.php', ['grant_type' => 'refresh_token', 'refresh_token' => $refresh['json']['refresh_token'], 'client_id' => $client->client_id]);
		$this->assertSame(400, $answer['code']);
		$this->assertSame('invalid_grant', $answer['json']['error'], 'offline_access was withdrawn from the client');
	}

	/**
	 * A code created before the sessions of its user were invalidated is refused
	 *
	 * @return void
	 */
	public function testCodeRefusedAfterSessionInvalidation()
	{
		global $db, $user;
		$client = $this->newClient();
		$code = $this->newCode($client);
		$resql = $db->query("SELECT flagdelsessionsbefore FROM ".$db->prefix()."user WHERE rowid = ".((int) $user->id));
		$obj = ($resql ? $db->fetch_object($resql) : null);
		$savedflag = (($obj && $obj->flagdelsessionsbefore !== null) ? "'".$db->escape($obj->flagdelsessionsbefore)."'" : "NULL");
		$db->query("UPDATE ".$db->prefix()."oauth_authcode SET datec = '".$db->idate(dol_now() - 7200)."' WHERE code_hash = '".$db->escape(oauthserverHash($code))."'");
		$db->query("UPDATE ".$db->prefix()."user SET flagdelsessionsbefore = '".$db->idate(dol_now() - 3600, 'gmt')."' WHERE rowid = ".((int) $user->id));
		$this->commitAndRestart();
		try {
			$answer = $this->exchange($client, $code);
		} finally {
			$db->query("UPDATE ".$db->prefix()."user SET flagdelsessionsbefore = ".$savedflag." WHERE rowid = ".((int) $user->id));
			$this->commitAndRestart();
		}
		$this->assertSame(400, $answer['code']);
		$this->assertSame('invalid_grant', $answer['json']['error']);
	}

	/**
	 * Revocation of an access token
	 *
	 * @return void
	 */
	public function testRevoke()
	{
		global $db;
		$client = $this->newClient();
		$tokens = $this->exchange($client, $this->newCode($client))['json'];

		$answer = $this->post('revoke.php', ['token' => $tokens['access_token'], 'client_id' => $client->client_id]);
		$this->assertSame(200, $answer['code']);

		$this->commitAndRestart();
		$v = new OAuthServerToken($db);
		$this->assertSame(-1, $v->validateAccessToken($tokens['access_token'], 'mcp'));
	}

	/**
	 * Method and grant type errors
	 *
	 * @return void
	 */
	public function testProtocolErrors()
	{
		$client = $this->newClient();

		$result = getURLContent($this->requestUrl('token.php'), 'GET', '', 0, $this->requestHeaders(), ['https', 'http'], 2);
		$this->assertSame(405, (int) $result['http_code']);

		$answer = $this->post('token.php', ['grant_type' => 'password', 'client_id' => $client->client_id]);
		$this->assertSame('unsupported_grant_type', $answer['json']['error']);

		$answer = $this->post('token.php', ['grant_type' => 'authorization_code', 'client_id' => 'unknown']);
		$this->assertSame(401, $answer['code']);
	}
}
