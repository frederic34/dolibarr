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
 * \file    htdocs/oauthserver/class/oauthservertoken.class.php
 * \ingroup oauthserver
 * \brief   Grant of the OAuth 2.1 authorization server: an access token and an optional refresh token
 */

require_once DOL_DOCUMENT_ROOT.'/core/class/commonobject.class.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';


/**
 * Grant stored in llx_oauth_token with service 'dolibarr_oauth'. Only SHA-256
 * hashes of the tokens are stored; the plain tokens exist in memory right
 * after issue() or rotate().
 */
class OAuthServerToken extends CommonObject
{
	/**
	 * @var string Module
	 */
	public $module = 'oauthserver';

	/**
	 * @var string Element type
	 */
	public $element = 'oauthserver_token';

	/**
	 * @var string Table without prefix
	 */
	public $table_element = 'oauth_token';

	const SERVICE = 'dolibarr_oauth';
	const ACCESS_PREFIX = 'dolat_';
	const REFRESH_PREFIX = 'dolrt_';

	/**
	 * Seconds after a rotation during which the previous refresh token is
	 * refused without revoking the grant (two parallel refreshes).
	 */
	const REFRESH_GRACE = 30;

	/**
	 * @var int User the grant was given by
	 */
	public $fk_user = 0;

	/**
	 * @var int Client the grant was given to
	 */
	public $fk_oauth_client = 0;

	/**
	 * @var string[] Granted scopes
	 */
	public $scopes = [];

	/**
	 * @var int Expiry of the access token
	 */
	public $expire_at = 0;

	/**
	 * @var ?int Expiry of the refresh token, null without refresh token
	 */
	public $expire_refresh_at = null;

	/**
	 * @var ?int Date of the last rotation
	 */
	public $date_refresh = null;

	/**
	 * @var int Creation date of the grant
	 */
	public $datec = 0;

	/**
	 * @var ?int Last use on a resource server
	 */
	public $lastaccess = null;

	/**
	 * @var int Status of the client, loaded by validateAccessToken()
	 */
	public $client_status = 0;

	/**
	 * @var string Hash of the current refresh token, loaded by fetch methods
	 */
	private $refreshhash = '';

	/**
	 * @var string Plain access token, only after issue() or rotate()
	 */
	public $access_token = '';

	/**
	 * @var string Plain refresh token, only after issue() or rotate()
	 */
	public $refresh_token = '';

	/**
	 * @var string OAuth error code set by validateAccessToken()
	 */
	public $error_code = '';

	/**
	 * @var string Description of the error set by validateAccessToken()
	 */
	public $error_description = '';

	/**
	 * @var string Output of the cron job
	 */
	public $output = '';


	/**
	 * Constructor
	 *
	 * @param DoliDB $db Database handler
	 */
	public function __construct(DoliDB $db)
	{
		$this->db = $db;
	}

	/**
	 * Lifetime of an access token, in seconds.
	 *
	 * @return int Seconds
	 */
	public static function getAccessLifetime()
	{
		return max(60, getDolGlobalInt('OAUTHSERVER_ACCESS_TOKEN_LIFETIME', 3600));
	}

	/**
	 * Lifetime of a refresh token, in seconds, counted from its last rotation.
	 *
	 * @return int Seconds
	 */
	public static function getRefreshLifetime()
	{
		return max(3600, getDolGlobalInt('OAUTHSERVER_REFRESH_TOKEN_LIFETIME', 2592000));
	}

	/**
	 * Create a grant. The plain tokens are left in $this->access_token and $this->refresh_token.
	 * The caller manages the transaction.
	 *
	 * @param	User		$user		User running the request (for the trigger)
	 * @param	int			$fkclient	Client id
	 * @param	int			$fkuser		User who consented
	 * @param	string[]	$scopes		Granted scopes
	 * @param	int			$entity		Entity of the grant
	 * @return	int						Id if OK, -1 if KO
	 */
	public function issue(User $user, $fkclient, $fkuser, $scopes, $entity)
	{
		$now = dol_now();

		$this->fk_oauth_client = (int) $fkclient;
		$this->fk_user = (int) $fkuser;
		$this->scopes = array_values($scopes);
		$this->entity = (int) $entity;
		$this->access_token = oauthserverGenerateSecret(self::ACCESS_PREFIX);
		$this->refresh_token = (in_array('offline_access', $this->scopes, true) ? oauthserverGenerateSecret(self::REFRESH_PREFIX) : '');
		$this->expire_at = $now + self::getAccessLifetime();
		$this->expire_refresh_at = ($this->refresh_token !== '' ? $now + self::getRefreshLifetime() : null);
		$this->refreshhash = ($this->refresh_token !== '' ? oauthserverHash($this->refresh_token) : '');
		$this->datec = $now;

		$sql = "INSERT INTO ".$this->db->prefix().$this->table_element;
		$sql .= " (service, tokenstring, tokenstring_refresh, expire_at, expire_refresh_at, state, fk_user, fk_oauth_client, entity, datec)";
		$sql .= " VALUES ('".$this->db->escape(self::SERVICE)."'";
		$sql .= ", '".$this->db->escape(oauthserverHash($this->access_token))."'";
		$sql .= ", ".($this->refreshhash === '' ? "NULL" : "'".$this->db->escape($this->refreshhash)."'");
		$sql .= ", '".$this->db->idate($this->expire_at)."'";
		$sql .= ", ".($this->expire_refresh_at === null ? "NULL" : "'".$this->db->idate($this->expire_refresh_at)."'");
		$sql .= ", '".$this->db->escape(implode(' ', $this->scopes))."'";
		$sql .= ", ".((int) $this->fk_user);
		$sql .= ", ".((int) $this->fk_oauth_client);
		$sql .= ", ".((int) $this->entity);
		$sql .= ", '".$this->db->idate($now)."')";

		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$this->id = $this->db->last_insert_id($this->db->prefix().$this->table_element);

		$this->context['audit'] = 'client='.$this->fk_oauth_client.' user='.$this->fk_user.' scope='.implode(' ', $this->scopes);
		if ($this->call_trigger('OAUTHSERVER_GRANT_CREATE', $user) < 0) {
			return -1;
		}

		return $this->id;
	}

	/**
	 * Fill the properties from a row.
	 *
	 * @param	object	$obj	Row with the columns selected by the fetch methods
	 * @return	void
	 */
	private function setFromRow($obj)
	{
		$this->id = (int) $obj->rowid;
		$this->entity = (int) $obj->entity;
		$this->fk_user = (int) $obj->fk_user;
		$this->fk_oauth_client = (int) $obj->fk_oauth_client;
		$this->scopes = oauthserverParseScopes((string) $obj->state);
		$this->expire_at = (int) $this->db->jdate($obj->expire_at);
		$this->expire_refresh_at = ($obj->expire_refresh_at === null ? null : (int) $this->db->jdate($obj->expire_refresh_at));
		$this->date_refresh = ($obj->date_refresh === null ? null : (int) $this->db->jdate($obj->date_refresh));
		$this->datec = (int) $this->db->jdate($obj->datec);
		$this->lastaccess = ($obj->lastaccess === null ? null : (int) $this->db->jdate($obj->lastaccess));
		$this->refreshhash = (string) $obj->tokenstring_refresh;
	}

	/**
	 * Load a grant by id.
	 *
	 * @param	int		$id		Id
	 * @return	int				1 if found, 0 if not, -1 on error
	 */
	public function fetch($id)
	{
		$sql = "SELECT rowid, entity, fk_user, fk_oauth_client, state, expire_at, expire_refresh_at, date_refresh, datec, lastaccess, tokenstring_refresh";
		$sql .= " FROM ".$this->db->prefix().$this->table_element;
		$sql .= " WHERE rowid = ".((int) $id)." AND service = '".$this->db->escape(self::SERVICE)."'";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return 0;
		}
		$this->setFromRow($obj);

		return 1;
	}

	/**
	 * Load a grant from a refresh token, current or replaced by the last rotation.
	 *
	 * @param	string	$refresh	Refresh token sent by the client
	 * @return	int					1 current token, 2 previous token (reuse), 0 unknown, -1 error
	 */
	public function fetchByRefreshToken($refresh)
	{
		if (strpos($refresh, self::REFRESH_PREFIX) !== 0) {
			return 0;
		}
		$hash = oauthserverHash($refresh);

		$sql = "SELECT rowid, entity, fk_user, fk_oauth_client, state, expire_at, expire_refresh_at, date_refresh, datec, lastaccess, tokenstring_refresh";
		$sql .= " FROM ".$this->db->prefix().$this->table_element;
		$sql .= " WHERE service = '".$this->db->escape(self::SERVICE)."'";
		$sql .= " AND (tokenstring_refresh = '".$this->db->escape($hash)."' OR tokenstring_refresh_previous = '".$this->db->escape($hash)."')";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return 0;
		}
		$this->setFromRow($obj);

		return (hash_equals($this->refreshhash, $hash) ? 1 : 2);
	}

	/**
	 * Load a grant from its access token, expired or not (used by the revocation endpoint).
	 *
	 * @param	string	$access		Access token
	 * @return	int					1 if found, 0 if not, -1 on error
	 */
	public function fetchByAccessToken($access)
	{
		if (strpos($access, self::ACCESS_PREFIX) !== 0) {
			return 0;
		}
		$sql = "SELECT rowid, entity, fk_user, fk_oauth_client, state, expire_at, expire_refresh_at, date_refresh, datec, lastaccess, tokenstring_refresh";
		$sql .= " FROM ".$this->db->prefix().$this->table_element;
		$sql .= " WHERE service = '".$this->db->escape(self::SERVICE)."'";
		$sql .= " AND tokenstring = '".$this->db->escape(oauthserverHash($access))."'";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return 0;
		}
		$this->setFromRow($obj);

		return 1;
	}

	/**
	 * Whether the last rotation is recent enough for a reuse of the previous
	 * refresh token to be a race between two refreshes, not a theft.
	 *
	 * @return bool True inside the grace period
	 */
	public function isInRefreshGrace()
	{
		return ($this->date_refresh !== null && (dol_now() - $this->date_refresh) < self::REFRESH_GRACE);
	}

	/**
	 * Rotate the tokens of a grant loaded by fetchByRefreshToken(). Only one of
	 * two concurrent rotations of the same refresh token succeeds.
	 *
	 * @param	string[]	$scopes		Scopes of the new tokens (subset of the current ones)
	 * @return	int						1 if OK, 0 if another rotation won, -1 on error
	 */
	public function rotate($scopes)
	{
		$now = dol_now();
		$access = oauthserverGenerateSecret(self::ACCESS_PREFIX);
		$refresh = oauthserverGenerateSecret(self::REFRESH_PREFIX);
		$expireat = $now + self::getAccessLifetime();
		$expirerefreshat = $now + self::getRefreshLifetime();

		$sql = "UPDATE ".$this->db->prefix().$this->table_element." SET";
		$sql .= " tokenstring_refresh_previous = '".$this->db->escape($this->refreshhash)."'";
		$sql .= ", tokenstring = '".$this->db->escape(oauthserverHash($access))."'";
		$sql .= ", tokenstring_refresh = '".$this->db->escape(oauthserverHash($refresh))."'";
		$sql .= ", expire_at = '".$this->db->idate($expireat)."'";
		$sql .= ", expire_refresh_at = '".$this->db->idate($expirerefreshat)."'";
		$sql .= ", date_refresh = '".$this->db->idate($now)."'";
		$sql .= ", state = '".$this->db->escape(implode(' ', $scopes))."'";
		$sql .= " WHERE rowid = ".((int) $this->id);
		$sql .= " AND service = '".$this->db->escape(self::SERVICE)."'";
		$sql .= " AND tokenstring_refresh = '".$this->db->escape($this->refreshhash)."'";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		if ($this->db->affected_rows($resql) != 1) {
			return 0;
		}

		$this->access_token = $access;
		$this->refresh_token = $refresh;
		$this->refreshhash = oauthserverHash($refresh);
		$this->expire_at = $expireat;
		$this->expire_refresh_at = $expirerefreshat;
		$this->date_refresh = $now;
		$this->scopes = array_values($scopes);

		return 1;
	}

	/**
	 * Delete the grant: its access and refresh tokens stop working at once.
	 *
	 * @param	User	$user			User revoking (for the trigger)
	 * @param	string	$triggercode	Security event to record, '' for none
	 * @return	int						1 if OK, -1 if KO
	 */
	public function revoke(User $user, $triggercode = 'OAUTHSERVER_GRANT_REVOKE')
	{
		$sql = "DELETE FROM ".$this->db->prefix().$this->table_element;
		$sql .= " WHERE rowid = ".((int) $this->id)." AND service = '".$this->db->escape(self::SERVICE)."'";

		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return -1;
		}

		if ($triggercode !== '') {
			$this->context['audit'] = 'grant='.$this->id.' client='.$this->fk_oauth_client.' user='.$this->fk_user;
			if ($this->call_trigger($triggercode, $user) < 0) {
				return -1;
			}
		}

		return 1;
	}

	/**
	 * Validate an access token presented to a resource server. Does not send
	 * anything and does not touch the global user. The scopes loaded are those
	 * of the grant still allowed to the client, so that narrowing the scopes of
	 * a client applies at once to the tokens it already holds.
	 *
	 * @param	string	$token		Bearer value
	 * @param	string	$audience	'api' or 'mcp'
	 * @return	int					1 if valid (properties loaded), -1 with error_code and error_description set
	 */
	public function validateAccessToken($token, $audience)
	{
		$this->error_code = 'invalid_token';
		$this->error_description = 'The access token is not valid';

		if (strpos($token, self::ACCESS_PREFIX) !== 0) {
			return -1;
		}

		$sql = "SELECT oat.rowid, oat.entity, oat.fk_user, oat.fk_oauth_client, oat.state, oat.expire_at, oat.expire_refresh_at, oat.date_refresh,";
		$sql .= " oat.datec, oat.lastaccess, oat.tokenstring_refresh, c.status as client_status, c.allowed_scopes as client_scopes, u.flagdelsessionsbefore";
		$sql .= " FROM ".$this->db->prefix().$this->table_element." as oat";
		$sql .= " INNER JOIN ".$this->db->prefix()."oauth_client as c ON c.rowid = oat.fk_oauth_client";
		$sql .= " INNER JOIN ".$this->db->prefix()."user as u ON u.rowid = oat.fk_user";
		$sql .= " WHERE oat.service = '".$this->db->escape(self::SERVICE)."'";
		$sql .= " AND oat.tokenstring = '".$this->db->escape(oauthserverHash($token))."'";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return -1;
		}
		$this->setFromRow($obj);
		$this->client_status = (int) $obj->client_status;
		$this->scopes = array_values(array_intersect($this->scopes, oauthserverParseScopes((string) $obj->client_scopes)));

		if ($this->expire_at <= dol_now()) {
			$this->error_description = 'The access token expired';
			return -1;
		}
		if ($this->client_status !== OAuthServerClient::STATUS_ENABLED) {
			$this->error_description = 'The client of this access token is disabled';
			return -1;
		}
		$flag = ($obj->flagdelsessionsbefore === null ? 0 : (int) $this->db->jdate($obj->flagdelsessionsbefore, 'gmt'));
		if ($flag > 0 && $this->datec < $flag) {
			$this->error_description = 'The sessions of the user were invalidated after this grant';
			return -1;
		}
		if (!in_array($audience, $this->scopes, true)) {
			$this->error_code = 'insufficient_scope';
			$this->error_description = 'This access token is not valid for this resource';
			return -1;
		}

		$this->error_code = '';
		$this->error_description = '';

		return 1;
	}

	/**
	 * Whether the user can still use this grant: enabled, inside the validity
	 * dates, sessions not invalidated after the grant was created.
	 *
	 * @param	User	$tokenuser	User of the grant, loaded
	 * @return	bool				True if allowed
	 */
	public function isUserAllowed(User $tokenuser)
	{
		if ((int) $tokenuser->status !== User::STATUS_ENABLED || $tokenuser->isNotIntoValidityDateRange()) {
			return false;
		}
		if (!empty($tokenuser->flagdelsessionsbefore) && $this->datec < (int) $tokenuser->flagdelsessionsbefore) {
			return false;
		}

		return true;
	}

	/**
	 * Whether a scope was granted.
	 *
	 * @param	string	$scope	Scope
	 * @return	bool			True if granted
	 */
	public function hasScope($scope)
	{
		return in_array($scope, $this->scopes, true);
	}

	/**
	 * Cron job: delete expired codes, expired grants and dynamic clients never used.
	 *
	 * @return int 0 if OK, <>0 if KO (cron convention)
	 */
	public function purgeExpired()
	{
		$now = dol_now();
		$sqls = [];
		$sqls[] = "DELETE FROM ".$this->db->prefix()."oauth_authcode WHERE expire_at < '".$this->db->idate($now - 86400)."'";

		$sql = "DELETE FROM ".$this->db->prefix().$this->table_element." WHERE service = '".$this->db->escape(self::SERVICE)."'";
		$sql .= " AND ((expire_refresh_at IS NOT NULL AND expire_refresh_at < '".$this->db->idate($now)."')";
		$sql .= " OR (expire_refresh_at IS NULL AND expire_at < '".$this->db->idate($now)."'))";
		$sqls[] = $sql;

		$sql = "DELETE FROM ".$this->db->prefix()."oauth_client WHERE registration_type = 'dynamic' AND date_last_use IS NULL";
		$sql .= " AND datec < '".$this->db->idate($now - 30 * 86400)."'";
		$sqls[] = $sql;

		$nb = 0;
		foreach ($sqls as $sql) {
			$resql = $this->db->query($sql);
			if (!$resql) {
				$this->error = $this->db->lasterror();
				$this->output = $this->error;
				return 1;
			}
			$nb += (int) $this->db->affected_rows($resql);
		}
		$this->output = $nb.' row(s) deleted';

		return 0;
	}
}
