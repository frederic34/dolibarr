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
 * \file    htdocs/oauthserver/class/oauthserverauthcode.class.php
 * \ingroup oauthserver
 * \brief   Authorization code of the OAuth 2.1 authorization server
 */

require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';


/**
 * Authorization code (table llx_oauth_authcode). Valid 60 s, redeemed once.
 * The row is kept after redemption so that a replay can be detected.
 */
class OAuthServerAuthCode
{
	/**
	 * Lifetime of a code, in seconds
	 */
	const LIFETIME = 60;

	/**
	 * @var DoliDB Database handler
	 */
	public $db;

	/**
	 * @var int Id
	 */
	public $id = 0;

	/**
	 * @var int Entity
	 */
	public $entity = 1;

	/**
	 * @var int Client id (rowid of llx_oauth_client)
	 */
	public $fk_oauth_client = 0;

	/**
	 * @var int User who consented
	 */
	public $fk_user = 0;

	/**
	 * @var string Redirect URI of the authorization request
	 */
	public $redirect_uri = '';

	/**
	 * @var string[] Granted scopes
	 */
	public $scopes = [];

	/**
	 * @var string Resource indicator (RFC 8707)
	 */
	public $resource = '';

	/**
	 * @var string PKCE challenge
	 */
	public $code_challenge = '';

	/**
	 * @var string PKCE method, always S256
	 */
	public $code_challenge_method = 'S256';

	/**
	 * @var int Expiry timestamp
	 */
	public $expire_at = 0;

	/**
	 * @var int Creation timestamp
	 */
	public $datec = 0;

	/**
	 * @var ?int Redemption timestamp
	 */
	public $date_used = null;

	/**
	 * @var int Grant created on redemption
	 */
	public $fk_oauth_token = 0;

	/**
	 * @var string Error
	 */
	public $error = '';


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
	 * Store a new code from the properties.
	 *
	 * @return string Plain code to send to the client, '' on error
	 */
	public function create()
	{
		$code = oauthserverGenerateSecret('', 32);
		$now = dol_now();
		$this->expire_at = $now + self::LIFETIME;
		$this->datec = $now;

		$sql = "INSERT INTO ".$this->db->prefix()."oauth_authcode";
		$sql .= " (entity, code_hash, fk_oauth_client, fk_user, redirect_uri, scope, resource, code_challenge, code_challenge_method, expire_at, datec)";
		$sql .= " VALUES (".((int) $this->entity);
		$sql .= ", '".$this->db->escape(oauthserverHash($code))."'";
		$sql .= ", ".((int) $this->fk_oauth_client);
		$sql .= ", ".((int) $this->fk_user);
		$sql .= ", '".$this->db->escape($this->redirect_uri)."'";
		$sql .= ", '".$this->db->escape(implode(' ', $this->scopes))."'";
		$sql .= ", ".($this->resource === '' ? "NULL" : "'".$this->db->escape($this->resource)."'");
		$sql .= ", '".$this->db->escape($this->code_challenge)."'";
		$sql .= ", '".$this->db->escape($this->code_challenge_method)."'";
		$sql .= ", '".$this->db->idate($this->expire_at)."'";
		$sql .= ", '".$this->db->idate($now)."')";

		if (!$this->db->query($sql)) {
			$this->error = $this->db->lasterror();
			return '';
		}
		$this->id = $this->db->last_insert_id($this->db->prefix()."oauth_authcode");

		return $code;
	}

	/**
	 * Load a code from its plain value.
	 *
	 * @param	string	$code	Code sent by the client
	 * @return	int				1 if found, 0 if not, -1 on error
	 */
	public function fetchByCode($code)
	{
		if ($code === '') {
			return 0;
		}
		$sql = "SELECT rowid, entity, fk_oauth_client, fk_user, redirect_uri, scope, resource, code_challenge, code_challenge_method, expire_at, date_used, fk_oauth_token, datec";
		$sql .= " FROM ".$this->db->prefix()."oauth_authcode";
		$sql .= " WHERE code_hash = '".$this->db->escape(oauthserverHash($code))."'";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}
		$obj = $this->db->fetch_object($resql);
		if (!$obj) {
			return 0;
		}

		$this->id = (int) $obj->rowid;
		$this->entity = (int) $obj->entity;
		$this->fk_oauth_client = (int) $obj->fk_oauth_client;
		$this->fk_user = (int) $obj->fk_user;
		$this->redirect_uri = (string) $obj->redirect_uri;
		$this->scopes = oauthserverParseScopes((string) $obj->scope);
		$this->resource = (string) $obj->resource;
		$this->code_challenge = (string) $obj->code_challenge;
		$this->code_challenge_method = (string) $obj->code_challenge_method;
		$this->expire_at = (int) $this->db->jdate($obj->expire_at);
		$this->date_used = ($obj->date_used === null ? null : (int) $this->db->jdate($obj->date_used));
		$this->fk_oauth_token = (int) $obj->fk_oauth_token;
		$this->datec = (int) $this->db->jdate($obj->datec);

		return 1;
	}

	/**
	 * Whether the code is past its lifetime.
	 *
	 * @return bool True if expired
	 */
	public function isExpired()
	{
		return $this->expire_at <= dol_now();
	}

	/**
	 * Mark the code as redeemed. Only one caller can succeed.
	 *
	 * @param	int		$fktoken	Grant created with this code
	 * @return	int					1 if marked now, 0 if it was already used, -1 on error
	 */
	public function markUsed($fktoken)
	{
		$sql = "UPDATE ".$this->db->prefix()."oauth_authcode";
		$sql .= " SET date_used = '".$this->db->idate(dol_now())."', fk_oauth_token = ".((int) $fktoken);
		$sql .= " WHERE rowid = ".((int) $this->id)." AND date_used IS NULL";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}

		return ($this->db->affected_rows($resql) == 1 ? 1 : 0);
	}
}
