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
 * \defgroup   oauthserver     Module OAuth Server
 * \brief      OAuth 2.1 authorization server for the REST API and the MCP server
 *
 * \file       htdocs/core/modules/modOAuthServer.class.php
 * \ingroup    oauthserver
 * \brief      Description and activation file of the module OAuth Server
 */
include_once DOL_DOCUMENT_ROOT.'/core/modules/DolibarrModules.class.php';


/**
 * Description and activation class of the module OAuth Server
 */
class modOAuthServer extends DolibarrModules
{
	/**
	 * Constructor. Define names, constants, directories, boxes, permissions
	 *
	 * @param DoliDB $db Database handler
	 */
	public function __construct($db)
	{
		$this->db = $db;

		$this->numero = 69000;
		$this->rights_class = 'oauthserver';
		$this->family = "interface";
		$this->module_position = '27';
		$this->name = preg_replace('/^mod/i', '', get_class($this));
		$this->description = "OAuth 2.1 authorization server for the REST API and the MCP server";
		$this->version = 'experimental';
		$this->const_name = 'MAIN_MODULE_'.strtoupper($this->name);
		$this->picto = 'technic';

		$this->module_parts = [];
		$this->dirs = [];
		$this->config_page_url = ["setup.php@oauthserver"];

		$this->hidden = false;
		$this->depends = [];
		$this->requiredby = [];
		$this->conflictwith = [];
		$this->langfiles = ["oauthserver"];
		$this->phpmin = [7, 1];
		$this->need_dolibarr_version = [25, -3];

		$this->const = [
			0 => ['OAUTHSERVER_ACCESS_TOKEN_LIFETIME', 'chaine', '3600', 'Lifetime of the OAuth access tokens, in seconds', 0, 'current', 0],
			1 => ['OAUTHSERVER_REFRESH_TOKEN_LIFETIME', 'chaine', '2592000', 'Lifetime of the OAuth refresh tokens, in seconds, extended at each refresh', 0, 'current', 0],
			2 => ['OAUTHSERVER_DCR_SCOPES', 'chaine', 'mcp read write offline_access', 'Scopes allowed to dynamically registered clients', 0, 'current', 0],
			3 => ['OAUTHSERVER_DCR_MAX_PER_HOUR', 'chaine', '20', 'Maximum number of dynamic client registrations per hour', 0, 'current', 0],
		];

		$this->tabs = [
			['data' => 'user:+oauthapps:OAuthConnectedApplications:oauthserver:isModEnabled("oauthserver"):/oauthserver/user_grants.php?id=__ID__'],
		];
		$this->dictionaries = [];
		$this->boxes = [];

		$this->cronjobs = [
			0 => [
				'label' => 'OAuthServerPurgeExpired',
				'jobtype' => 'method',
				'class' => '/oauthserver/class/oauthservertoken.class.php',
				'objectname' => 'OAuthServerToken',
				'method' => 'purgeExpired',
				'parameters' => '',
				'comment' => 'OAuthServerPurgeExpiredComment',
				'frequency' => 1,
				'unitfrequency' => 86400,
				'status' => 1,
				'test' => 'isModEnabled("oauthserver")',
				'priority' => 50,
			],
		];

		$this->rights = [];
		$this->menu = [];
	}

	/**
	 * Function called when module is enabled.
	 * Creates the module tables (llx_oauth_client, llx_oauth_authcode).
	 *
	 * @param string $options Options when enabling module ('', 'noboxes')
	 * @return int<-1,1> 1 if OK, <=0 if KO
	 */
	public function init($options = '')
	{
		$result = $this->_load_tables('/install/mysql/', 'oauthserver');
		if ($result < 0) {
			return -1;
		}

		return $this->_init([], $options);
	}

	/**
	 * Function called when module is disabled. Tables and tokens are kept.
	 *
	 * @param string $options Options when disabling module ('', 'noboxes')
	 * @return int<-1,1> 1 if OK, <=0 if KO
	 */
	public function remove($options = '')
	{
		return $this->_remove([], $options);
	}
}
