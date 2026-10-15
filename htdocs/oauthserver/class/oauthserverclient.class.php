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
 * \file    htdocs/oauthserver/class/oauthserverclient.class.php
 * \ingroup oauthserver
 * \brief   Application registered as a client of the OAuth 2.1 authorization server
 */

require_once DOL_DOCUMENT_ROOT.'/core/class/commonobject.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';


/**
 * Client of the OAuth server (table llx_oauth_client)
 */
class OAuthServerClient extends CommonObject
{
	/**
	 * @var string Module
	 */
	public $module = 'oauthserver';

	/**
	 * @var string Element type
	 */
	public $element = 'oauthserver_client';

	/**
	 * @var string Table without prefix
	 */
	public $table_element = 'oauth_client';

	/**
	 * @var string Picto
	 */
	public $picto = 'technic';

	const STATUS_DISABLED = 0;
	const STATUS_ENABLED = 1;

	/**
	 * Accepted values of token_endpoint_auth_method
	 */
	const AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post'];

	/**
	 * @var string Public identifier of the client
	 */
	public $client_id = '';

	/**
	 * @var ?string password_hash() of the secret, null for a public client
	 */
	public $client_secret_hash = null;

	/**
	 * @var string Plain secret. Only set by create(), to be shown once; never stored.
	 */
	public $client_secret_plain = '';

	/**
	 * @var string Name of the application, shown on the consent screen
	 */
	public $label = '';

	/**
	 * @var string[] Exact redirect URIs
	 */
	public $redirect_uris = [];

	/**
	 * @var string[] Scopes the client may request
	 */
	public $allowed_scopes = [];

	/**
	 * @var string One of AUTH_METHODS
	 */
	public $token_endpoint_auth_method = 'none';

	/**
	 * @var string 'admin' (created by an administrator) or 'dynamic' (RFC 7591)
	 */
	public $registration_type = 'admin';

	/**
	 * @var int|string Creation date
	 */
	public $datec;

	/**
	 * @var int|string|null Date of the last token issued to this client
	 */
	public $date_last_use = null;


	/**
	 * Constructor
	 *
	 * @param DoliDB $db Database handler
	 */
	public function __construct(DoliDB $db)
	{
		$this->db = $db;
		$this->ismultientitymanaged = 1;
		$this->status = self::STATUS_ENABLED;
	}

	/**
	 * Check the fields before an insert or an update. Sets $this->error to a lang key.
	 *
	 * @return bool True if valid
	 */
	private function checkFields()
	{
		$this->label = trim((string) $this->label);
		if ($this->label === '') {
			$this->error = 'ErrorOAuthClientLabelRequired';
			return false;
		}
		$this->redirect_uris = array_values(array_unique(array_map('trim', $this->redirect_uris)));
		if (empty($this->redirect_uris)) {
			$this->error = 'ErrorOAuthClientRedirectUriRequired';
			return false;
		}
		foreach ($this->redirect_uris as $uri) {
			if (!oauthserverIsValidRedirectUri($uri)) {
				$this->error = 'ErrorOAuthClientBadRedirectUri';
				$this->errors = [$uri];
				return false;
			}
		}
		if (!in_array($this->token_endpoint_auth_method, self::AUTH_METHODS, true)) {
			$this->error = 'ErrorOAuthClientBadAuthMethod';
			return false;
		}
		$this->allowed_scopes = array_values(array_unique($this->allowed_scopes));
		if (empty($this->allowed_scopes) || array_diff($this->allowed_scopes, oauthserverGetSupportedScopes())
			|| (!in_array('api', $this->allowed_scopes, true) && !in_array('mcp', $this->allowed_scopes, true))) {
			$this->error = 'ErrorOAuthClientBadScopes';
			return false;
		}
		if (!in_array($this->registration_type, ['admin', 'dynamic'], true)) {
			$this->registration_type = 'admin';
		}

		return true;
	}

	/**
	 * Create the client. A confidential client gets a secret, readable once in $this->client_secret_plain.
	 *
	 * @param	User	$user		User creating the client (empty user for a dynamic registration)
	 * @param	int		$notrigger	1 to disable the trigger
	 * @return	int					Id if OK, <0 if KO
	 */
	public function create(User $user, $notrigger = 0)
	{
		global $conf;

		if (!$this->checkFields()) {
			return -1;
		}
		if (empty($this->entity)) {
			$this->entity = (int) $conf->entity;
		}
		if ($this->client_id === '') {
			$this->client_id = oauthserverGenerateSecret('', 16);
		}
		$this->client_secret_hash = null;
		$this->client_secret_plain = '';
		if ($this->token_endpoint_auth_method !== 'none') {
			$this->client_secret_plain = oauthserverGenerateSecret('dolcs_');
			$this->client_secret_hash = password_hash($this->client_secret_plain, PASSWORD_DEFAULT);
		}
		$now = dol_now();

		$this->db->begin();

		$sql = "INSERT INTO ".$this->db->prefix().$this->table_element;
		$sql .= " (entity, client_id, client_secret_hash, label, redirect_uris, allowed_scopes, token_endpoint_auth_method, registration_type, status, fk_user_creat, datec)";
		$sql .= " VALUES (".((int) $this->entity);
		$sql .= ", '".$this->db->escape($this->client_id)."'";
		$sql .= ", ".($this->client_secret_hash === null ? "NULL" : "'".$this->db->escape($this->client_secret_hash)."'");
		$sql .= ", '".$this->db->escape($this->label)."'";
		$sql .= ", '".$this->db->escape((string) json_encode($this->redirect_uris, JSON_UNESCAPED_SLASHES))."'";
		$sql .= ", '".$this->db->escape(implode(' ', $this->allowed_scopes))."'";
		$sql .= ", '".$this->db->escape($this->token_endpoint_auth_method)."'";
		$sql .= ", '".$this->db->escape($this->registration_type)."'";
		$sql .= ", ".((int) $this->status);
		$sql .= ", ".(empty($user->id) ? "NULL" : ((int) $user->id));
		$sql .= ", '".$this->db->idate($now)."')";

		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			$this->db->rollback();
			return -1;
		}
		$this->id = $this->db->last_insert_id($this->db->prefix().$this->table_element);
		$this->fk_user_creat = empty($user->id) ? null : (int) $user->id;
		$this->datec = $now;

		if (!$notrigger) {
			$this->context['audit'] = 'client_id='.$this->client_id.' label='.$this->label.' type='.$this->registration_type;
			if ($this->call_trigger('OAUTHSERVER_CLIENT_CREATE', $user) < 0) {
				$this->db->rollback();
				return -1;
			}
		}

		$this->db->commit();

		return $this->id;
	}

	/**
	 * Load a client by id or by client_id. No entity filter: callers check the entity.
	 *
	 * @param	int		$id			Id, or 0 to use $clientid
	 * @param	string	$clientid	Public client identifier
	 * @return	int					1 if found, 0 if not found, -1 on error
	 */
	public function fetch($id, $clientid = '')
	{
		$sql = "SELECT rowid, entity, client_id, client_secret_hash, label, redirect_uris, allowed_scopes, token_endpoint_auth_method,";
		$sql .= " registration_type, status, fk_user_creat, datec, date_last_use";
		$sql .= " FROM ".$this->db->prefix().$this->table_element;
		if ($id > 0) {
			$sql .= " WHERE rowid = ".((int) $id);
		} elseif ($clientid !== '') {
			$sql .= " WHERE client_id = '".$this->db->escape($clientid)."'";
		} else {
			return -1;
		}

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return 0;
		}

		$uris = json_decode((string) $obj->redirect_uris, true);

		$this->id = (int) $obj->rowid;
		$this->entity = (int) $obj->entity;
		$this->client_id = (string) $obj->client_id;
		$this->client_secret_hash = ($obj->client_secret_hash === null ? null : (string) $obj->client_secret_hash);
		$this->client_secret_plain = '';
		$this->label = (string) $obj->label;
		$this->redirect_uris = is_array($uris) ? array_values(array_filter($uris, 'is_string')) : [];
		$this->allowed_scopes = oauthserverParseScopes((string) $obj->allowed_scopes);
		$this->token_endpoint_auth_method = (string) $obj->token_endpoint_auth_method;
		$this->registration_type = (string) $obj->registration_type;
		$this->status = (int) $obj->status;
		$this->fk_user_creat = ($obj->fk_user_creat === null ? null : (int) $obj->fk_user_creat);
		$this->datec = $this->db->jdate($obj->datec);
		$this->date_last_use = ($obj->date_last_use === null ? null : $this->db->jdate($obj->date_last_use));

		return 1;
	}

	/**
	 * Update label, redirect URIs, allowed scopes and status. The secret and the auth method do not change.
	 *
	 * @param	User	$user		User making the change
	 * @param	int		$notrigger	Not used, kept for the CommonObject signature
	 * @return	int					1 if OK, <0 if KO
	 */
	public function update(User $user, $notrigger = 0)
	{
		if (!$this->checkFields()) {
			return -1;
		}

		$sql = "UPDATE ".$this->db->prefix().$this->table_element." SET";
		$sql .= " label = '".$this->db->escape($this->label)."'";
		$sql .= ", redirect_uris = '".$this->db->escape((string) json_encode($this->redirect_uris, JSON_UNESCAPED_SLASHES))."'";
		$sql .= ", allowed_scopes = '".$this->db->escape(implode(' ', $this->allowed_scopes))."'";
		$sql .= ", status = ".((int) $this->status);
		$sql .= " WHERE rowid = ".((int) $this->id);

		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}

		return 1;
	}

	/**
	 * Change the status only, without validating the other fields, so that a stored client
	 * that no longer validates can still be disabled.
	 *
	 * @param	User	$user		User making the change
	 * @param	int		$status		STATUS_DISABLED or STATUS_ENABLED
	 * @return	int					1 if OK, <0 if KO
	 */
	public function setStatus(User $user, $status)
	{
		$status = (int) $status;
		if ($this->id <= 0 || !in_array($status, [self::STATUS_DISABLED, self::STATUS_ENABLED], true)) {
			$this->error = 'ErrorBadParameters';
			return -1;
		}

		$sql = "UPDATE ".$this->db->prefix().$this->table_element." SET status = ".((int) $status);
		$sql .= " WHERE rowid = ".((int) $this->id);
		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}

		$this->status = $status;

		return 1;
	}

	/**
	 * Delete the client with its authorization codes and its grants.
	 *
	 * @param	User	$user		User deleting
	 * @param	int		$notrigger	1 to disable the trigger
	 * @return	int					1 if OK, <0 if KO
	 */
	public function delete(User $user, $notrigger = 0)
	{
		$this->db->begin();

		$sqls = [
			"DELETE FROM ".$this->db->prefix()."oauth_authcode WHERE fk_oauth_client = ".((int) $this->id),
			"DELETE FROM ".$this->db->prefix()."oauth_token WHERE service = 'dolibarr_oauth' AND fk_oauth_client = ".((int) $this->id),
			"DELETE FROM ".$this->db->prefix().$this->table_element." WHERE rowid = ".((int) $this->id),
		];
		foreach ($sqls as $sql) {
			if (!$this->db->query($sql)) {
				$this->error = $this->db->lasterror();
				$this->db->rollback();
				return -1;
			}
		}

		if (!$notrigger) {
			$this->context['audit'] = 'client_id='.$this->client_id.' label='.$this->label;
			if ($this->call_trigger('OAUTHSERVER_CLIENT_DELETE', $user) < 0) {
				$this->db->rollback();
				return -1;
			}
		}

		$this->db->commit();

		return 1;
	}

	/**
	 * Authenticate the client of a token or revocation request and load it.
	 *
	 * @param	array{client_id:string,client_secret:string,method:string}	$credentials	Result of oauthserverGetClientCredentials()
	 * @return	int		1 if authenticated, -1 otherwise
	 */
	public function authenticate($credentials)
	{
		$methods = ['none' => 'none', 'basic' => 'client_secret_basic', 'post' => 'client_secret_post'];

		if ($credentials['client_id'] === '' || !isset($methods[$credentials['method']])) {
			return -1;
		}
		if ($this->fetch(0, $credentials['client_id']) <= 0 || (int) $this->status !== self::STATUS_ENABLED) {
			return -1;
		}
		$expected = $methods[$credentials['method']];
		if ($expected !== $this->token_endpoint_auth_method) {
			return -1;
		}
		if ($expected !== 'none' && !password_verify($credentials['client_secret'], (string) $this->client_secret_hash)) {
			return -1;
		}

		return 1;
	}

	/**
	 * Whether the URI is one of the registered redirect URIs: exact string comparison,
	 * except for the port of an http loopback URI, which native applications choose
	 * when they start (RFC 8252 section 7.3).
	 *
	 * @param	string	$uri	Redirect URI of the request
	 * @return	bool			True if registered
	 */
	public function hasRedirectUri($uri)
	{
		if (in_array($uri, $this->redirect_uris, true)) {
			return true;
		}
		$requested = self::loopbackUriWithoutPort($uri);
		if ($requested === '') {
			return false;
		}
		foreach ($this->redirect_uris as $registered) {
			if (self::loopbackUriWithoutPort($registered) === $requested) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Valid http loopback redirect URI with its port removed.
	 *
	 * @param	string	$uri	Redirect URI
	 * @return	string			URI without port, or '' if it is not a valid http loopback URI
	 */
	private static function loopbackUriWithoutPort($uri)
	{
		$reg = [];
		if (!oauthserverIsValidRedirectUri($uri) || !preg_match('/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?([\/?].*)?$/iD', $uri, $reg)) {
			return '';
		}

		return 'http://'.strtolower($reg[1]).(isset($reg[2]) ? $reg[2] : '');
	}

	/**
	 * Whether the client has no secret.
	 *
	 * @return bool True for a public client
	 */
	public function isPublic()
	{
		return $this->token_endpoint_auth_method === 'none';
	}

	/**
	 * Record that a token was issued to this client.
	 *
	 * @return int 1 if OK, -1 if KO
	 */
	public function markUsed()
	{
		$sql = "UPDATE ".$this->db->prefix().$this->table_element." SET date_last_use = '".$this->db->idate(dol_now())."' WHERE rowid = ".((int) $this->id);

		return $this->db->query($sql) ? 1 : -1;
	}

	/**
	 * Link to the client card.
	 *
	 * @param	int		$withpicto	1 to add the picto
	 * @return	string				HTML link
	 */
	public function getNomUrl($withpicto = 0)
	{
		$url = DOL_URL_ROOT.'/oauthserver/client_card.php?id='.((int) $this->id);

		return '<a href="'.dol_escape_htmltag($url).'">'.($withpicto ? img_picto('', $this->picto, 'class="pictofixedwidth"') : '').dol_escape_htmltag($this->label).'</a>';
	}

	/**
	 * Label of the status of this client.
	 *
	 * @param	int		$mode	0=long label, 5=short label + picto
	 * @return	string			Label
	 */
	public function getLibStatut($mode = 0)
	{
		return $this->LibStatut((int) $this->status, $mode);
	}

	// phpcs:disable PEAR.NamingConventions.ValidFunctionName.ScopeNotCamelCaps
	/**
	 * Label of a status.
	 *
	 * @param	int		$status		Status
	 * @param	int		$mode		0=long label, 5=short label + picto
	 * @return	string				Label
	 */
	public function LibStatut($status, $mode = 0)
	{
		// phpcs:enable
		global $langs;

		$label = ($status == self::STATUS_ENABLED ? $langs->transnoentitiesnoconv('Enabled') : $langs->transnoentitiesnoconv('Disabled'));

		return dolGetStatus($label, $label, '', ($status == self::STATUS_ENABLED ? 'status4' : 'status5'), $mode);
	}
}
