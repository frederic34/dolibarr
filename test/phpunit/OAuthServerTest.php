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
 * \file    test/phpunit/OAuthServerTest.php
 * \ingroup test
 * \brief   PHPUnit tests of the OAuth Server module helpers and classes
 */

global $conf, $user, $langs, $db;
require_once dirname(__FILE__).'/../../htdocs/master.inc.php';
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
 * Class for PHPUnit tests
 */
class OAuthServerTest extends CommonClassTest
{
	/**
	 * Enable the module when the database does not have it (its tables are created on activation)
	 *
	 * @return void
	 */
	public static function setUpBeforeClass(): void
	{
		global $db, $conf;

		if (!isModEnabled('oauthserver')) {
			// Activating a module runs its SQL scripts (CREATE TABLE), an implicit commit: do it
			// before the test transaction is opened. The module stays enabled, as after a manual
			// activation (same as DonTest).
			require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
			$result = activateModule('modOAuthServer');
			self::assertEmpty($result['errors'], 'Failed to activate module oauthserver: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}

		self::assertTrue(isModEnabled('oauthserver'), 'module oauthserver must be enabled');

		parent::setUpBeforeClass();
	}

	/**
	 * base64url without padding
	 *
	 * @return void
	 */
	public function testBase64UrlEncode()
	{
		$this->assertSame('-_8', oauthserverBase64UrlEncode("\xfb\xff"));
		$this->assertSame('YWJj', oauthserverBase64UrlEncode('abc'));
	}

	/**
	 * Random credentials have the prefix and 43 base64url chars for 32 bytes
	 *
	 * @return void
	 */
	public function testGenerateSecret()
	{
		$a = oauthserverGenerateSecret('dolat_');
		$b = oauthserverGenerateSecret('dolat_');
		$this->assertSame(1, preg_match('/^dolat_[A-Za-z0-9_-]{43}$/', $a));
		$this->assertNotSame($a, $b);
		$this->assertSame(1, preg_match('/^[A-Za-z0-9_-]{22}$/', oauthserverGenerateSecret('', 16)));
	}

	/**
	 * Stored hash format
	 *
	 * @return void
	 */
	public function testHash()
	{
		$this->assertSame('sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', oauthserverHash('abc'));
	}

	/**
	 * PKCE S256 with the vector of RFC 7636 appendix B
	 *
	 * @return void
	 */
	public function testPkceRfc7636Vector()
	{
		$verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		$challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		$this->assertTrue(oauthserverCheckPkce($verifier, $challenge));
		$this->assertFalse(oauthserverCheckPkce($verifier.'x', $challenge));
		$this->assertFalse(oauthserverCheckPkce('tooshort', $challenge));
		$this->assertFalse(oauthserverCheckPkce($verifier, ''));
		// Fix round 1: a trailing newline is not in the charset, a 129-char verifier is too long
		$this->assertFalse(oauthserverCheckPkce($verifier."\n", $challenge));
		$this->assertFalse(oauthserverCheckPkce(str_repeat('a', 129), $challenge));
		// A non-string challenge is refused instead of making hash_equals() throw on PHP 8
		$this->assertFalse(oauthserverCheckPkce($verifier, null));
	}

	/**
	 * Scope parsing drops duplicates and blanks
	 *
	 * @return void
	 */
	public function testParseScopes()
	{
		$this->assertSame(['mcp', 'read'], oauthserverParseScopes('  mcp read  mcp '));
		$this->assertSame([], oauthserverParseScopes(''));
	}

	/**
	 * Scope resolution rules of spec section 4
	 *
	 * @return void
	 */
	public function testResolveScopes()
	{
		$all = ['api', 'mcp', 'read', 'write', 'offline_access'];
		$error = '';

		$this->assertSame(['api', 'mcp', 'offline_access', 'read', 'write'], oauthserverResolveScopes('', $all, '', $error));
		$this->assertSame(['mcp', 'read'], oauthserverResolveScopes('read mcp', $all, '', $error));

		$this->assertNull(oauthserverResolveScopes('mcp admin', $all, '', $error));
		$this->assertSame('invalid_scope', $error);

		$this->assertNull(oauthserverResolveScopes('read', $all, '', $error));
		$this->assertSame('invalid_scope', $error);

		$this->assertNull(oauthserverResolveScopes('api', ['mcp', 'read'], '', $error));
		$this->assertSame('invalid_scope', $error);

		$mcpurl = oauthserverGetResourceUrl('mcp');
		$apiurl = oauthserverGetResourceUrl('api');
		$this->assertSame(['mcp', 'offline_access', 'read', 'write'], oauthserverResolveScopes('', $all, $mcpurl, $error));
		$this->assertSame(['api', 'read'], oauthserverResolveScopes('mcp read', $all, $apiurl, $error));

		$this->assertNull(oauthserverResolveScopes('mcp', $all, 'https://evil.example/', $error));
		$this->assertSame('invalid_target', $error);
	}

	/**
	 * Redirect URI rules: https, or http on loopback only, no fragment
	 *
	 * @return void
	 */
	public function testIsValidRedirectUri()
	{
		foreach (['https://claude.ai/api/mcp/auth_callback', 'http://127.0.0.1:33418/callback', 'http://localhost/cb', 'http://[::1]:8080/cb', 'https://app.example/cb?x=1'] as $uri) {
			$this->assertTrue(oauthserverIsValidRedirectUri($uri), $uri);
		}
		foreach (['http://example.com/cb', 'https://app.example/cb#frag', 'javascript:alert(1)', 'claude://cb', '', '/relative', 'https:///nohost'] as $uri) {
			$this->assertFalse(oauthserverIsValidRedirectUri($uri), $uri);
		}
	}

	/**
	 * Review focus 1: existing query string and reserved characters in state
	 *
	 * @return void
	 */
	public function testBuildRedirectUrl()
	{
		$url = oauthserverBuildRedirectUrl('https://app.example/cb?x=1', ['code' => 'abc', 'state' => 'a b&c=d', 'iss' => 'https://h/oauthserver']);
		$this->assertSame('https://app.example/cb?x=1&code=abc&state=a%20b%26c%3Dd&iss=https%3A%2F%2Fh%2Foauthserver', $url);

		$url = oauthserverBuildRedirectUrl('https://app.example/cb', ['error' => 'access_denied', 'state' => '']);
		$this->assertSame('https://app.example/cb?error=access_denied', $url);
	}

	/**
	 * Review focus 4: Dolibarr installed under a sub-path or on a port
	 *
	 * @return void
	 */
	public function testUrlsWithSubPath()
	{
		$root = 'https://host.example/dolibarr';
		$this->assertSame('https://host.example/dolibarr/oauthserver', oauthserverGetIssuer($root));
		$this->assertSame('https://host.example/.well-known/oauth-authorization-server/dolibarr/oauthserver', oauthserverGetWellKnownUrl($root));
		$this->assertSame('https://host.example/dolibarr/ai/server/mcp_server.php', oauthserverGetResourceUrl('mcp', $root));
		$this->assertSame('https://host.example/dolibarr/api/index.php', oauthserverGetResourceUrl('api', $root));
		$this->assertSame('https://h:8443/.well-known/oauth-authorization-server/oauthserver', oauthserverGetWellKnownUrl('https://h:8443'));
	}

	/**
	 * Client credentials in the Basic header, in the body, or none
	 *
	 * @return void
	 */
	public function testClientCredentials()
	{
		$_GET = [];

		$_POST = [];
		$cred = oauthserverGetClientCredentials(['HTTP_AUTHORIZATION' => 'Basic '.base64_encode('cid:sec%3Aret')]);
		$this->assertSame(['client_id' => 'cid', 'client_secret' => 'sec:ret', 'method' => 'basic'], $cred);

		// Apache CGI/FastCGI republishes the header as REDIRECT_HTTP_AUTHORIZATION
		$cred = oauthserverGetClientCredentials(['REDIRECT_HTTP_AUTHORIZATION' => 'Basic '.base64_encode('cid:sec')]);
		$this->assertSame(['client_id' => 'cid', 'client_secret' => 'sec', 'method' => 'basic'], $cred);

		$_POST = ['client_id' => 'cid', 'client_secret' => 'dolcs_abc'];
		$cred = oauthserverGetClientCredentials([]);
		$this->assertSame(['client_id' => 'cid', 'client_secret' => 'dolcs_abc', 'method' => 'post'], $cred);

		$_POST = ['client_id' => 'cid'];
		$cred = oauthserverGetClientCredentials([]);
		$this->assertSame(['client_id' => 'cid', 'client_secret' => '', 'method' => 'none'], $cred);

		// Fix round 1: credentials in the query string are never read (RFC 6749 section 2.3.1)
		$_GET = ['client_id' => 'cid', 'client_secret' => 'dolcs_abc'];
		$_POST = [];
		$cred = oauthserverGetClientCredentials([]);
		$this->assertSame(['client_id' => '', 'client_secret' => '', 'method' => 'none'], $cred);

		$_GET = [];
		$_POST = [];
	}

	/**
	 * Fix round 1: a malformed body credential is refused as a conflict, not dropped
	 *
	 * @return void
	 */
	public function testClientCredentialsMalformed()
	{
		$_GET = [];
		$_POST = ['client_id' => 'cid', 'client_secret' => 'bad secret!'];
		$cred = oauthserverGetClientCredentials([]);
		$this->assertSame('conflict', $cred['method']);

		$_POST = ['client_id' => 'cid/x'];
		$cred = oauthserverGetClientCredentials([]);
		$this->assertSame('conflict', $cred['method']);

		$_POST = [];
	}

	/**
	 * Review focus 5: credentials sent two ways are refused
	 *
	 * @return void
	 */
	public function testClientCredentialsConflict()
	{
		$_GET = [];
		$_POST = ['client_secret' => 'dolcs_abc'];
		$cred = oauthserverGetClientCredentials(['HTTP_AUTHORIZATION' => 'Basic '.base64_encode('cid:other')]);
		$this->assertSame('conflict', $cred['method']);

		$_POST = ['client_id' => 'another'];
		$cred = oauthserverGetClientCredentials(['HTTP_AUTHORIZATION' => 'Basic '.base64_encode('cid:other')]);
		$this->assertSame('conflict', $cred['method']);

		$_POST = [];
	}

	/**
	 * HTTPS detection
	 *
	 * @return void
	 */
	public function testIsSecureRequest()
	{
		global $conf;
		$saved = getDolGlobalString('OAUTHSERVER_ALLOW_HTTP');
		$conf->global->OAUTHSERVER_ALLOW_HTTP = '';

		$this->assertTrue(oauthserverIsSecureRequest(['HTTPS' => 'on']));
		$this->assertTrue(oauthserverIsSecureRequest(['SERVER_PORT' => '443']));
		$this->assertFalse(oauthserverIsSecureRequest(['HTTPS' => 'off', 'SERVER_PORT' => '80']));

		$conf->global->OAUTHSERVER_ALLOW_HTTP = '1';
		$this->assertTrue(oauthserverIsSecureRequest(['SERVER_PORT' => '80']));

		$conf->global->OAUTHSERVER_ALLOW_HTTP = $saved;
	}

	/**
	 * Create a client for the tests
	 *
	 * @param	string	$method		token_endpoint_auth_method
	 * @param	string	$scopes		Allowed scopes
	 * @return	OAuthServerClient	Created client
	 */
	private function createTestClient($method = 'none', $scopes = 'api mcp read write offline_access')
	{
		global $db, $user;

		$client = new OAuthServerClient($db);
		$client->label = 'PHPUnit client '.$method;
		$client->redirect_uris = ['https://app.example/cb', 'http://127.0.0.1:33418/cb'];
		$client->allowed_scopes = oauthserverParseScopes($scopes);
		$client->token_endpoint_auth_method = $method;
		$result = $client->create($user);
		$this->assertGreaterThan(0, $result, 'create client: '.$client->error);

		return $client;
	}

	/**
	 * Create, fetch by id and by client_id, update, delete
	 *
	 * @return void
	 */
	public function testClientCrud()
	{
		global $db, $user;

		$client = $this->createTestClient('client_secret_basic');
		$this->assertSame(1, preg_match('/^[A-Za-z0-9_-]{22}$/', $client->client_id));
		$this->assertSame(1, preg_match('/^dolcs_[A-Za-z0-9_-]{43}$/', $client->client_secret_plain));
		$this->assertTrue(password_verify($client->client_secret_plain, (string) $client->client_secret_hash));

		$fetched = new OAuthServerClient($db);
		$this->assertSame(1, $fetched->fetch($client->id));
		$this->assertSame($client->client_id, $fetched->client_id);
		$this->assertSame(['https://app.example/cb', 'http://127.0.0.1:33418/cb'], $fetched->redirect_uris);
		$this->assertSame(['api', 'mcp', 'read', 'write', 'offline_access'], $fetched->allowed_scopes);
		$this->assertSame('', $fetched->client_secret_plain, 'the plain secret is never read back');

		$byid = new OAuthServerClient($db);
		$this->assertSame(1, $byid->fetch(0, $client->client_id));
		$this->assertSame($client->id, $byid->id);
		$this->assertSame(0, $byid->fetch(0, 'doesnotexist'));

		$fetched->label = 'Renamed';
		$fetched->status = OAuthServerClient::STATUS_DISABLED;
		$this->assertSame(1, $fetched->update($user));
		$again = new OAuthServerClient($db);
		$again->fetch($client->id);
		$this->assertSame('Renamed', $again->label);
		$this->assertSame(0, (int) $again->status);

		$this->assertSame(1, $again->delete($user));
		$this->assertSame(0, (new OAuthServerClient($db))->fetch($client->id));
	}

	/**
	 * Deleting a client deletes its authorization codes and its grants
	 *
	 * @return void
	 */
	public function testClientDeleteCascades()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$code = new OAuthServerAuthCode($db);
		$code->fk_oauth_client = $client->id;
		$code->fk_user = (int) $user->id;
		$code->redirect_uri = 'https://app.example/cb';
		$code->scopes = ['mcp', 'read'];
		$code->code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		$plain = $code->create();
		$this->assertNotSame('', $plain);
		$grant = new OAuthServerToken($db);
		$this->assertGreaterThan(0, $grant->issue($user, $client->id, (int) $user->id, ['mcp', 'read'], 1));

		$this->assertSame(1, $client->delete($user));
		$this->assertSame(0, (new OAuthServerAuthCode($db))->fetchByCode($plain), 'the codes of the client are deleted');
		$this->assertSame(0, (new OAuthServerToken($db))->fetch($grant->id), 'the grants of the client are deleted');
	}

	/**
	 * Loopback redirect URIs match whatever the port (RFC 8252 section 7.3), other URIs exactly
	 *
	 * @return void
	 */
	public function testHasRedirectUriLoopbackPort()
	{
		global $db;

		$client = new OAuthServerClient($db);
		$client->redirect_uris = ['https://app.example/cb', 'http://127.0.0.1:33418/cb', 'http://localhost/cb'];

		$this->assertTrue($client->hasRedirectUri('https://app.example/cb'));
		$this->assertTrue($client->hasRedirectUri('http://127.0.0.1:33418/cb'));
		$this->assertTrue($client->hasRedirectUri('http://127.0.0.1:50123/cb'), 'any port on a loopback address');
		$this->assertTrue($client->hasRedirectUri('http://127.0.0.1/cb'));
		$this->assertTrue($client->hasRedirectUri('http://localhost:8080/cb'));

		$this->assertFalse($client->hasRedirectUri('http://127.0.0.1:50123/other'), 'the path must match');
		$this->assertFalse($client->hasRedirectUri('http://localhost:33418/cb?x=1'), 'the query must match');
		$this->assertFalse($client->hasRedirectUri('http://[::1]:33418/cb'), 'the host must match');
		$this->assertFalse($client->hasRedirectUri('https://127.0.0.1:33418/cb'), 'the scheme must match');
		$this->assertFalse($client->hasRedirectUri('https://app.example:8443/cb'), 'the port of a non loopback URI must match');
		$this->assertFalse($client->hasRedirectUri('http://127.0.0.1:1@evil.example/cb'));
		$this->assertFalse($client->hasRedirectUri(''));
	}

	/**
	 * A stored client that no longer validates can still be disabled
	 *
	 * @return void
	 */
	public function testSetStatusWithoutValidation()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$this->assertTrue((bool) $db->query("UPDATE ".$db->prefix()."oauth_client SET allowed_scopes = 'read' WHERE rowid = ".((int) $client->id)));

		$fetched = new OAuthServerClient($db);
		$this->assertSame(1, $fetched->fetch($client->id));
		$this->assertSame(-1, $fetched->update($user), 'update() validates the stored fields');
		$this->assertSame(1, $fetched->setStatus($user, OAuthServerClient::STATUS_DISABLED));
		$this->assertSame(-1, $fetched->setStatus($user, 7));

		$again = new OAuthServerClient($db);
		$again->fetch($client->id);
		$this->assertSame(0, (int) $again->status);
		$this->assertSame(['read'], $again->allowed_scopes, 'only the status changed');

		$again->delete($user);
	}

	/**
	 * Field validation on create
	 *
	 * @return void
	 */
	public function testClientValidation()
	{
		global $db, $user;

		$client = new OAuthServerClient($db);
		$client->label = 'Bad';
		$client->redirect_uris = ['http://example.com/cb'];
		$client->allowed_scopes = ['mcp'];
		$this->assertLessThan(0, $client->create($user));
		$this->assertSame('ErrorOAuthClientBadRedirectUri', $client->error);

		$client->redirect_uris = ['https://app.example/cb'];
		$client->allowed_scopes = ['read'];
		$this->assertLessThan(0, $client->create($user));
		$this->assertSame('ErrorOAuthClientBadScopes', $client->error);

		$client->allowed_scopes = ['mcp'];
		$client->token_endpoint_auth_method = 'private_key_jwt';
		$this->assertLessThan(0, $client->create($user));
		$this->assertSame('ErrorOAuthClientBadAuthMethod', $client->error);

		$client->token_endpoint_auth_method = 'none';
		$client->label = '  ';
		$this->assertLessThan(0, $client->create($user));
		$this->assertSame('ErrorOAuthClientLabelRequired', $client->error);
	}

	/**
	 * Client authentication with each method
	 *
	 * @return void
	 */
	public function testClientAuthenticate()
	{
		global $db;

		$basic = $this->createTestClient('client_secret_basic');
		$public = $this->createTestClient('none');

		$c = new OAuthServerClient($db);
		$this->assertSame(1, $c->authenticate(['client_id' => $basic->client_id, 'client_secret' => $basic->client_secret_plain, 'method' => 'basic']));
		$this->assertSame(-1, $c->authenticate(['client_id' => $basic->client_id, 'client_secret' => 'dolcs_wrong', 'method' => 'basic']));
		$this->assertSame(-1, $c->authenticate(['client_id' => $basic->client_id, 'client_secret' => $basic->client_secret_plain, 'method' => 'post']), 'method must match the registered one');
		$this->assertSame(-1, $c->authenticate(['client_id' => $basic->client_id, 'client_secret' => '', 'method' => 'none']), 'a confidential client cannot skip its secret');
		$this->assertSame(1, $c->authenticate(['client_id' => $public->client_id, 'client_secret' => '', 'method' => 'none']));
		$this->assertSame(-1, $c->authenticate(['client_id' => '', 'client_secret' => '', 'method' => 'conflict']));

		$public->status = OAuthServerClient::STATUS_DISABLED;
		$public->update($GLOBALS['user']);
		$this->assertSame(-1, $c->authenticate(['client_id' => $public->client_id, 'client_secret' => '', 'method' => 'none']));
	}

	/**
	 * Code: create, fetch by value, single use
	 *
	 * @return void
	 */
	public function testAuthCodeSingleUse()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$code = new OAuthServerAuthCode($db);
		$code->entity = 1;
		$code->fk_oauth_client = $client->id;
		$code->fk_user = (int) $user->id;
		$code->redirect_uri = 'https://app.example/cb';
		$code->scopes = ['mcp', 'read'];
		$code->code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		$plain = $code->create();
		$this->assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $plain));

		$loaded = new OAuthServerAuthCode($db);
		$this->assertSame(1, $loaded->fetchByCode($plain));
		$this->assertSame(['mcp', 'read'], $loaded->scopes);
		$this->assertFalse($loaded->isExpired());
		$this->assertNull($loaded->date_used);
		$this->assertLessThanOrEqual(5, abs(dol_now() - $loaded->datec), 'the creation date is loaded');
		$this->assertSame(0, $loaded->fetchByCode('unknown'));

		$this->assertSame(1, $loaded->markUsed(123));
		$this->assertSame(0, $loaded->markUsed(456), 'a code is redeemed once');
		$again = new OAuthServerAuthCode($db);
		$again->fetchByCode($plain);
		$this->assertNotNull($again->date_used);
		$this->assertSame(123, $again->fk_oauth_token);
	}

	/**
	 * Issue a grant and validate its access token for each audience
	 *
	 * @return void
	 */
	public function testIssueAndValidate()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$id = $grant->issue($user, $client->id, (int) $user->id, ['mcp', 'offline_access', 'read'], 1);
		$this->assertGreaterThan(0, $id);
		$this->assertSame(1, preg_match('/^dolat_[A-Za-z0-9_-]{43}$/', $grant->access_token));
		$this->assertSame(1, preg_match('/^dolrt_[A-Za-z0-9_-]{43}$/', $grant->refresh_token));

		$v = new OAuthServerToken($db);
		$this->assertSame(1, $v->validateAccessToken($grant->access_token, 'mcp'));
		$this->assertSame((int) $user->id, $v->fk_user);
		$this->assertSame(['mcp', 'offline_access', 'read'], $v->scopes);
		$this->assertFalse($v->hasScope('write'));

		$this->assertSame(-1, $v->validateAccessToken($grant->access_token, 'api'));
		$this->assertSame('insufficient_scope', $v->error_code);

		$this->assertSame(-1, $v->validateAccessToken('dolat_unknown', 'mcp'));
		$this->assertSame('invalid_token', $v->error_code);
		$this->assertSame(-1, $v->validateAccessToken($grant->refresh_token, 'mcp'), 'a refresh token is not an access token');

		$byaccess = new OAuthServerToken($db);
		$this->assertSame(1, $byaccess->fetchByAccessToken($grant->access_token));
		$this->assertSame($grant->id, $byaccess->id);
		$this->assertSame(0, $byaccess->fetchByAccessToken($grant->refresh_token));

		$nooffline = new OAuthServerToken($db);
		$nooffline->issue($user, $client->id, (int) $user->id, ['api', 'read'], 1);
		$this->assertSame('', $nooffline->refresh_token, 'no refresh token without offline_access');
	}

	/**
	 * Expired access token, disabled client
	 *
	 * @return void
	 */
	public function testValidateRejectsExpiredAndDisabledClient()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['api', 'read'], 1);

		$db->query("UPDATE ".$db->prefix()."oauth_token SET expire_at = '".$db->idate(dol_now() - 10)."' WHERE rowid = ".((int) $grant->id));
		$v = new OAuthServerToken($db);
		$this->assertSame(-1, $v->validateAccessToken($grant->access_token, 'api'));
		$this->assertSame('invalid_token', $v->error_code);

		$grant2 = new OAuthServerToken($db);
		$grant2->issue($user, $client->id, (int) $user->id, ['api', 'read'], 1);
		$client->status = OAuthServerClient::STATUS_DISABLED;
		$client->update($user);
		$this->assertSame(-1, $v->validateAccessToken($grant2->access_token, 'api'));
		$this->assertSame('invalid_token', $v->error_code);
	}

	/**
	 * Narrowing the scopes allowed to a client applies to the grants it already has
	 *
	 * @return void
	 */
	public function testValidateUsesCurrentClientScopes()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['api', 'mcp', 'read', 'write'], 1);

		$client->allowed_scopes = ['api', 'mcp', 'read', 'offline_access'];
		$this->assertSame(1, $client->update($user));
		$v = new OAuthServerToken($db);
		$this->assertSame(1, $v->validateAccessToken($grant->access_token, 'api'));
		$this->assertSame(['api', 'mcp', 'read'], $v->scopes, 'write was withdrawn from the client');
		$this->assertFalse($v->hasScope('write'));

		$client->allowed_scopes = ['mcp', 'read'];
		$this->assertSame(1, $client->update($user));
		$this->assertSame(-1, $v->validateAccessToken($grant->access_token, 'api'), 'api was withdrawn from the client');
		$this->assertSame('insufficient_scope', $v->error_code);
		$this->assertSame(1, $v->validateAccessToken($grant->access_token, 'mcp'));
		$this->assertSame(['mcp', 'read'], $v->scopes);
	}

	/**
	 * Review focus 3: a grant created before "invalidate all sessions" is refused
	 *
	 * @return void
	 */
	public function testValidateRejectsGrantOlderThanSessionInvalidation()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['api', 'read'], 1);
		$db->query("UPDATE ".$db->prefix()."oauth_token SET datec = '".$db->idate(dol_now() - 3600)."' WHERE rowid = ".((int) $grant->id));
		$db->query("UPDATE ".$db->prefix()."user SET flagdelsessionsbefore = '".$db->idate(dol_now() - 60, 'gmt')."' WHERE rowid = ".((int) $user->id));

		$v = new OAuthServerToken($db);
		$this->assertSame(-1, $v->validateAccessToken($grant->access_token, 'api'));
		$this->assertSame('invalid_token', $v->error_code);

		$tokenuser = new User($db);
		$tokenuser->fetch($user->id);
		$loaded = new OAuthServerToken($db);
		$loaded->fetch($grant->id);
		$this->assertFalse($loaded->isUserAllowed($tokenuser));

		$db->query("UPDATE ".$db->prefix()."user SET flagdelsessionsbefore = NULL WHERE rowid = ".((int) $user->id));
	}

	/**
	 * Refresh rotation, then reuse of the old refresh token after the grace period revokes the grant
	 *
	 * @return void
	 */
	public function testRefreshRotationAndReuseRevokes()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['mcp', 'offline_access', 'read', 'write'], 1);
		$oldaccess = $grant->access_token;
		$oldrefresh = $grant->refresh_token;

		$r = new OAuthServerToken($db);
		$this->assertSame(1, $r->fetchByRefreshToken($oldrefresh));
		$this->assertSame(1, $r->rotate(['mcp', 'offline_access', 'read']));
		$this->assertNotSame($oldrefresh, $r->refresh_token);

		$v = new OAuthServerToken($db);
		$this->assertSame(-1, $v->validateAccessToken($oldaccess, 'mcp'), 'the old access token dies with the rotation');
		$this->assertSame(1, $v->validateAccessToken($r->access_token, 'mcp'));
		$this->assertSame(['mcp', 'offline_access', 'read'], $v->scopes, 'scopes can be narrowed at refresh');

		$old = new OAuthServerToken($db);
		$this->assertSame(2, $old->fetchByRefreshToken($oldrefresh));
		$this->assertTrue($old->isInRefreshGrace());

		$db->query("UPDATE ".$db->prefix()."oauth_token SET date_refresh = '".$db->idate(dol_now() - 120)."' WHERE rowid = ".((int) $grant->id));
		$old2 = new OAuthServerToken($db);
		$this->assertSame(2, $old2->fetchByRefreshToken($oldrefresh));
		$this->assertFalse($old2->isInRefreshGrace());
		$this->assertSame(1, $old2->revoke($user, 'OAUTHSERVER_REFRESH_REUSE'));
		$this->assertSame(-1, $v->validateAccessToken($r->access_token, 'mcp'), 'the whole grant is revoked');
	}

	/**
	 * Review focus 2: two parallel refreshes with the same token keep the grant alive
	 *
	 * @return void
	 */
	public function testRefreshRaceWithinGraceKeepsGrant()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['mcp', 'offline_access', 'read'], 1);

		$first = new OAuthServerToken($db);
		$second = new OAuthServerToken($db);
		$this->assertSame(1, $first->fetchByRefreshToken($grant->refresh_token));
		$this->assertSame(1, $second->fetchByRefreshToken($grant->refresh_token));
		$this->assertSame(1, $first->rotate($first->scopes));
		$this->assertSame(0, $second->rotate($second->scopes), 'the second rotation loses the race');

		$late = new OAuthServerToken($db);
		$this->assertSame(2, $late->fetchByRefreshToken($grant->refresh_token));
		$this->assertTrue($late->isInRefreshGrace(), 'the token endpoint answers invalid_grant without revoking');

		$v = new OAuthServerToken($db);
		$this->assertSame(1, $v->validateAccessToken($first->access_token, 'mcp'));
	}

	/**
	 * Cron purge
	 *
	 * @return void
	 */
	public function testPurgeExpired()
	{
		global $db, $user;

		$client = $this->createTestClient();
		$grant = new OAuthServerToken($db);
		$grant->issue($user, $client->id, (int) $user->id, ['api', 'read'], 1);
		$db->query("UPDATE ".$db->prefix()."oauth_token SET expire_at = '".$db->idate(dol_now() - 10)."' WHERE rowid = ".((int) $grant->id));

		$alive = new OAuthServerToken($db);
		$alive->issue($user, $client->id, (int) $user->id, ['api', 'offline_access', 'read'], 1);
		$db->query("UPDATE ".$db->prefix()."oauth_token SET expire_at = '".$db->idate(dol_now() - 10)."' WHERE rowid = ".((int) $alive->id));

		$purger = new OAuthServerToken($db);
		$this->assertSame(0, $purger->purgeExpired());
		$this->assertSame(0, (new OAuthServerToken($db))->fetch($grant->id), 'expired grant without refresh token is purged');
		$this->assertSame(1, (new OAuthServerToken($db))->fetch($alive->id), 'a grant whose refresh token is valid is kept');
	}

	/**
	 * Rewrite rules for an install under a sub-path
	 *
	 * @return void
	 */
	public function testRewriteRules()
	{
		$rules = oauthserverGetRewriteRules('https://host.example/dolibarr');
		$this->assertSame(
			"RewriteEngine On\nRewriteRule ^/?\\.well-known/oauth-authorization-server/dolibarr/oauthserver/?$ /dolibarr/oauthserver/metadata.php [L]",
			$rules['apache']
		);
		$this->assertSame(
			"location = /.well-known/oauth-authorization-server/dolibarr/oauthserver {\n    rewrite ^ /dolibarr/oauthserver/metadata.php last;\n}",
			$rules['nginx']
		);
	}

	/**
	 * A security event is recorded when its code is enabled
	 *
	 * @return void
	 */
	public function testSecurityEventRecorded()
	{
		global $db, $conf;

		$conf->global->MAIN_LOGEVENTS_OAUTHSERVER_CLIENT_CREATE = '1';
		$client = $this->createTestClient();
		unset($conf->global->MAIN_LOGEVENTS_OAUTHSERVER_CLIENT_CREATE);

		$resql = $db->query("SELECT description FROM ".$db->prefix()."events WHERE type = 'OAUTHSERVER_CLIENT_CREATE' ORDER BY rowid DESC".$db->plimit(1));
		$this->assertNotFalse($resql);
		$obj = $db->fetch_object($resql);
		$this->assertNotEmpty($obj, 'no security event recorded');
		$this->assertStringContainsString('client_id='.$client->client_id, (string) $obj->description);
	}
}
