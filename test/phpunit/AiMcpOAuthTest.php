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
 * \file    test/phpunit/AiMcpOAuthTest.php
 * \ingroup test
 * \brief   PHPUnit tests of the MCP server accepting OAuth access tokens
 */

global $conf, $user, $langs, $db;
require_once dirname(__FILE__).'/../../htdocs/master.inc.php';
require_once dirname(__FILE__).'/../../htdocs/core/lib/admin.lib.php';
require_once dirname(__FILE__).'/../../htdocs/ai/class/mcpauth.class.php';
require_once dirname(__FILE__).'/../../htdocs/ai/class/mcp.class.php';
require_once dirname(__FILE__).'/../../htdocs/ai/class/mcptool.class.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthserverclient.class.php';
require_once dirname(__FILE__).'/../../htdocs/oauthserver/class/oauthservertoken.class.php';
require_once dirname(__FILE__).'/../../htdocs/core/modules/modAi.class.php';
require_once dirname(__FILE__).'/CommonClassTest.class.php';

if (empty($user->id)) {
	print "Load permissions for admin user nb 1\n";
	$user->fetch(1);
	$user->loadRights();
}
$conf->global->MAIN_DISABLE_ALL_MAILS = 1;


/**
 * Tool that writes, for the read-only test
 */
class OAuthTestWriteTool extends McpTool
{
	/**
	 * @return array<int,array<string,mixed>> Definitions
	 */
	public function getDefinitions(): array
	{
		return [];
	}

	/**
	 * @param string				$toolName	Tool
	 * @param array<string,mixed>	$args		Arguments
	 * @return array<string,mixed>				Result
	 */
	public function execute(string $toolName, array $args)
	{
		return ['done' => true];
	}

	/**
	 * @param string $toolName Tool
	 * @return string Rights checked by the tool itself
	 */
	public function getRequiredRights(string $toolName)
	{
		return McpTool::RIGHTS_ENFORCED_DOWNSTREAM;
	}

	/**
	 * @param string				$toolName	Tool
	 * @param array<string,mixed>	$args		Arguments
	 * @return string							Preview
	 */
	public function writeConfirmationPreview(string $toolName, array $args)
	{
		return 'Would write something';
	}
}


/**
 * Tool of another module that does not say whether it writes, for the read-only test
 */
class OAuthTestUndeclaredTool extends McpTool
{
	/**
	 * @return array<int,array<string,mixed>> Definitions
	 */
	public function getDefinitions(): array
	{
		return [['name' => 'oauth_test_undeclared', 'description' => 'Test tool', 'inputSchema' => ['type' => 'object', 'properties' => new stdClass()]]];
	}

	/**
	 * @param string				$toolName	Tool
	 * @param array<string,mixed>	$args		Arguments
	 * @return array<string,mixed>				Result
	 */
	public function execute(string $toolName, array $args)
	{
		return ['done' => true];
	}

	/**
	 * @param string $toolName Tool
	 * @return string Rights checked by the tool itself
	 */
	public function getRequiredRights(string $toolName)
	{
		return McpTool::RIGHTS_ENFORCED_DOWNSTREAM;
	}
}


/**
 * Tool of another module that declares it only reads
 */
class OAuthTestDeclaredReadTool extends OAuthTestUndeclaredTool
{
	/**
	 * @return array<int,array<string,mixed>> Definitions
	 */
	public function getDefinitions(): array
	{
		return [['name' => 'oauth_test_declared_read', 'description' => 'Test tool', 'inputSchema' => ['type' => 'object', 'properties' => new stdClass()]]];
	}

	/**
	 * @param string				$toolName	Tool
	 * @param array<string,mixed>	$args		Arguments
	 * @return string							Nothing is written
	 */
	public function writeConfirmationPreview(string $toolName, array $args)
	{
		return McpTool::NO_WRITE;
	}
}


/**
 * Class for PHPUnit tests
 */
class AiMcpOAuthTest extends CommonClassTest
{
	/**
	 * @var bool Whether user 1 had the right to use the assistant before the test
	 */
	private $hadassistantright = false;

	/**
	 * @var string|null Value of AI_ASSISTANT_ALLOWED_TOOLS before the test, null if not set
	 */
	private $savedallowedtools = null;

	/**
	 * Enable the modules ai and oauthserver when the database does not have them
	 *
	 * @return void
	 */
	public static function setUpBeforeClass(): void
	{
		global $db, $conf;

		// Activating a module runs its SQL scripts (CREATE TABLE), an implicit commit: do it before
		// the test transaction is opened. The modules stay enabled (same as DonTest).
		if (!isModEnabled('ai')) {
			$result = activateModule('modAi');
			self::assertEmpty($result['errors'], 'Failed to activate module ai: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}
		if (!isModEnabled('oauthserver')) {
			$result = activateModule('modOAuthServer');
			self::assertEmpty($result['errors'], 'Failed to activate module oauthserver: '.implode(', ', $result['errors']));
			$conf->setValues($db);
		}
		self::assertTrue(isModEnabled('ai') && isModEnabled('oauthserver'), 'modules ai and oauthserver must be enabled');

		parent::setUpBeforeClass();
	}

	/**
	 * Give user 1 the right to use the assistant (inside the test transaction)
	 *
	 * @return void
	 */
	protected function setUp(): void
	{
		global $db, $user, $conf;
		parent::setUp();
		$this->savedallowedtools = (isset($conf->global->AI_ASSISTANT_ALLOWED_TOOLS) ? (string) $conf->global->AI_ASSISTANT_ALLOWED_TOOLS : null);
		$this->hadassistantright = $user->hasRight('ai', 'assistant', 'use');
		if (!$this->hadassistantright) {
			$modai = new modAi($db);
			$user->addrights($modai->numero + 1);
			$user->clearrights();
			$user->loadRights();
		}
	}

	/**
	 * Restore the rights of user 1 and the allowed tools
	 *
	 * @return void
	 */
	protected function tearDown(): void
	{
		global $db, $user, $conf;
		if (!$this->hadassistantright) {
			$modai = new modAi($db);
			$user->delrights($modai->numero + 1);
			$user->clearrights();
			$user->loadRights();
		}
		if ($this->savedallowedtools === null) {
			unset($conf->global->AI_ASSISTANT_ALLOWED_TOOLS);
		} else {
			$conf->global->AI_ASSISTANT_ALLOWED_TOOLS = $this->savedallowedtools;
		}
		parent::tearDown();
	}

	/**
	 * Issue a grant for user 1 (same connection, no commit needed)
	 *
	 * @param	string[]	$scopes		Scopes
	 * @return	OAuthServerToken		Grant
	 */
	private function newGrant($scopes)
	{
		global $db, $user;
		$client = new OAuthServerClient($db);
		$client->label = 'PHPUnit MCP';
		$client->redirect_uris = ['https://app.example/cb'];
		$client->allowed_scopes = ['api', 'mcp', 'read', 'write', 'offline_access'];
		$this->assertGreaterThan(0, $client->create($user, 1));
		$grant = new OAuthServerToken($db);
		$this->assertGreaterThan(0, $grant->issue($user, $client->id, (int) $user->id, $scopes, 1));

		return $grant;
	}

	/**
	 * A Bearer OAuth token with the mcp scope authenticates
	 *
	 * @return void
	 */
	public function testOAuthBearerAccepted()
	{
		global $db, $user;
		$grant = $this->newGrant(['mcp', 'read']);
		$auth = new McpAuth($db);
		$this->assertSame(1, $auth->authenticate(['HTTP_AUTHORIZATION' => 'Bearer '.$grant->access_token], []), $auth->error);
		$this->assertSame(McpAuth::MODE_OAUTH, $auth->mode);
		$this->assertSame((int) $user->id, $auth->userid);
		$this->assertSame(['mcp', 'read'], $auth->scopes);
		$this->assertTrue($auth->isReadOnly());

		$grantw = $this->newGrant(['mcp', 'read', 'write']);
		$this->assertSame(1, $auth->authenticate(['HTTP_AUTHORIZATION' => 'Bearer '.$grantw->access_token], []));
		$this->assertFalse($auth->isReadOnly());

		$used = new OAuthServerToken($db);
		$this->assertSame(1, $used->fetch($grantw->id));
		$this->assertNotNull($used->lastaccess, 'the last access of the grant is recorded');
	}

	/**
	 * Refusals: query string, api-only token, expired token
	 *
	 * @return void
	 */
	public function testOAuthRefusals()
	{
		global $db;
		$auth = new McpAuth($db);

		$grant = $this->newGrant(['mcp', 'read']);
		$this->assertSame(-1, $auth->authenticate([], ['DOLAPIKEY' => $grant->access_token]));
		$this->assertSame(401, $auth->httpcode);

		$apionly = $this->newGrant(['api', 'read']);
		$this->assertSame(-1, $auth->authenticate(['HTTP_AUTHORIZATION' => 'Bearer '.$apionly->access_token], []));
		$this->assertSame(403, $auth->httpcode);
		$this->assertSame('insufficient_scope', $auth->oauthErrorCode);

		$db->query("UPDATE ".$db->prefix()."oauth_token SET expire_at = '".$db->idate(dol_now() - 10)."' WHERE rowid = ".((int) $grant->id));
		$this->assertSame(-1, $auth->authenticate(['HTTP_AUTHORIZATION' => 'Bearer '.$grant->access_token], []));
		$this->assertSame(401, $auth->httpcode);
		$this->assertSame('invalid_token', $auth->oauthErrorCode);
	}

	/**
	 * Challenge header with resource metadata and error
	 *
	 * @return void
	 */
	public function testWwwAuthenticateHeader()
	{
		global $db;
		$auth = new McpAuth($db);
		$this->assertSame('Bearer realm="Dolibarr MCP"', $auth->getWwwAuthenticateHeader());
		$this->assertSame('Bearer realm="Dolibarr MCP", resource_metadata="https://h/prm", error="invalid_token"', $auth->getWwwAuthenticateHeader('https://h/prm', 'invalid_token'));
	}

	/**
	 * A read-only handler refuses a tool that writes, before any confirmation
	 *
	 * @return void
	 */
	public function testReadOnlyHandlerRefusesWrites()
	{
		global $db, $user, $conf;
		$conf->global->AI_ASSISTANT_ALLOWED_TOOLS = '';
		$handler = new McpHandler($db, $user, $conf, McpHandler::CTX_ASSISTANT);
		$handler->toolsByName['oauth_test_write'] = new OAuthTestWriteTool($db, $user, $conf);

		$handler->setReadOnly(true);
		$result = $handler->executeTool('oauth_test_write', []);
		$this->assertStringContainsString('read-only', (string) ($result['error'] ?? ''));

		$handler->setReadOnly(false);
		$result = $handler->executeTool('oauth_test_write', []);
		$this->assertStringNotContainsString('read-only', (string) json_encode($result));
	}

	/**
	 * Read-only fails closed for the tools of other modules that do not say whether they write
	 *
	 * @return void
	 */
	public function testReadOnlyHandlerRefusesUndeclaredExternalTools()
	{
		global $db, $user, $conf;
		$conf->global->AI_ASSISTANT_ALLOWED_TOOLS = '';
		$handler = new McpHandler($db, $user, $conf, McpHandler::CTX_ASSISTANT);
		self::callMethod($handler, 'registerTool', ['OAuthTestUndeclaredTool', new OAuthTestUndeclaredTool($db, $user, $conf), true]);
		self::callMethod($handler, 'registerTool', ['OAuthTestDeclaredReadTool', new OAuthTestDeclaredReadTool($db, $user, $conf), true]);

		$handler->setReadOnly(true);
		$result = $handler->executeTool('oauth_test_undeclared', []);
		$this->assertStringContainsString('read-only', (string) ($result['error'] ?? ''), 'an external tool without writeConfirmationPreview() is refused');
		$this->assertSame(['done' => true], $handler->executeTool('oauth_test_declared_read', []), 'an external tool declaring it reads runs');

		$handler->setReadOnly(false);
		$this->assertSame(['done' => true], $handler->executeTool('oauth_test_undeclared', []));

		// A native tool (not from the addMcpTools hook) without override is a read tool, as before
		$native = new McpHandler($db, $user, $conf, McpHandler::CTX_ASSISTANT);
		self::callMethod($native, 'registerTool', ['OAuthTestUndeclaredTool', new OAuthTestUndeclaredTool($db, $user, $conf)]);
		$native->setReadOnly(true);
		$this->assertSame(['done' => true], $native->executeTool('oauth_test_undeclared', []));
	}
}
