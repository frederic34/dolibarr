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
 * \file    htdocs/oauthserver/user_grants.php
 * \ingroup oauthserver
 * \brief   Tab of the user card listing the applications the user gave access to
 */

// Load Dolibarr environment
require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/usergroups.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthservertoken.class.php';

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(['users', 'oauthserver']);

$id = GETPOSTINT('id');
$action = GETPOST('action', 'aZ09');
$grantid = GETPOSTINT('grantid');

if (!isModEnabled('oauthserver') || $id <= 0) {
	accessforbidden();
}
// A user sees and revokes their own grants; an administrator those of everybody.
$permissiontorevoke = ($user->admin || (int) $user->id === $id);
if (!$permissiontorevoke) {
	accessforbidden();
}

$object = new User($db);
if ($object->fetch($id) <= 0) {
	accessforbidden();
}


/*
 * Actions
 */

if ($action == 'revoke' && $permissiontorevoke && $grantid > 0) {
	$grant = new OAuthServerToken($db);
	if ($grant->fetch($grantid) > 0 && (int) $grant->fk_user === (int) $object->id && (int) $grant->entity === (int) $conf->entity && $grant->revoke($user) > 0) {
		setEventMessages($langs->trans("OAuthGrantRevokedMessage"), null, 'mesgs');
	} else {
		setEventMessages($grant->error ? $grant->error : $langs->trans("Error"), null, 'errors');
	}
	header("Location: ".$_SERVER["PHP_SELF"].'?id='.((int) $object->id));
	exit;
}


/*
 * View
 */

llxHeader('', $langs->trans("OAuthConnectedApplications"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-user_grants');

$head = user_prepare_head($object);
print dol_get_fiche_head($head, 'oauthapps', $langs->trans("User"), -1, 'user');
dol_banner_tab($object, 'id', '', $user->hasRight('user', 'user', 'lire') || $user->admin);
print dol_get_fiche_end();

$sql = "SELECT oat.rowid, oat.state, oat.datec, oat.lastaccess, oat.expire_refresh_at, c.label, c.registration_type";
$sql .= " FROM ".$db->prefix()."oauth_token as oat";
$sql .= " INNER JOIN ".$db->prefix()."oauth_client as c ON c.rowid = oat.fk_oauth_client";
$sql .= " WHERE oat.service = '".$db->escape(OAuthServerToken::SERVICE)."'";
$sql .= " AND oat.fk_user = ".((int) $object->id);
$sql .= " AND oat.entity = ".((int) $conf->entity);
$sql .= $db->order('oat.datec', 'DESC');
$resql = $db->query($sql);
if (!$resql) {
	dol_print_error($db);
}

print '<br><div class="div-table-responsive"><table class="noborder centpercent">';
print '<tr class="liste_titre"><td>'.$langs->trans("OAuthClient").'</td><td>'.$langs->trans("OAuthScopes").'</td>';
print '<td>'.$langs->trans("DateCreation").'</td><td>'.$langs->trans("OAuthLastAccess").'</td><td>'.$langs->trans("OAuthRefreshExpiry").'</td><td></td></tr>';
$num = 0;
while ($resql && ($obj = $db->fetch_object($resql))) {
	$num++;
	print '<tr class="oddeven">';
	print '<td>'.dol_escape_htmltag($obj->label).($obj->registration_type === 'dynamic' ? ' <span class="badge badge-warning">'.$langs->trans("OAuthRegistrationDynamic").'</span>' : '').'</td>';
	print '<td>'.dol_escape_htmltag($obj->state).'</td>';
	print '<td>'.dol_print_date($db->jdate($obj->datec), 'dayhour').'</td>';
	print '<td>'.($obj->lastaccess ? dol_print_date($db->jdate($obj->lastaccess), 'dayhour') : '').'</td>';
	print '<td>'.($obj->expire_refresh_at ? dol_print_date($db->jdate($obj->expire_refresh_at), 'dayhour') : '').'</td>';
	print '<td class="right"><form method="POST" action="'.$_SERVER["PHP_SELF"].'">';
	print '<input type="hidden" name="token" value="'.newToken().'">';
	print '<input type="hidden" name="action" value="revoke">';
	print '<input type="hidden" name="id" value="'.((int) $object->id).'">';
	print '<input type="hidden" name="grantid" value="'.((int) $obj->rowid).'">';
	print '<input type="submit" class="button small butActionDelete" value="'.dolPrintHTMLForAttribute($langs->trans("OAuthRevoke")).'">';
	print '</form></td>';
	print '</tr>';
}
if ($num == 0) {
	print '<tr class="oddeven"><td colspan="6"><span class="opacitymedium">'.$langs->trans("OAuthNoConnectedApplication").'</span></td></tr>';
}
print '</table></div>';

llxFooter();
$db->close();
