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
 * \file    htdocs/oauthserver/client_list.php
 * \ingroup oauthserver
 * \brief   List of the client applications of the OAuth server
 */

// Load Dolibarr environment
require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/lib/oauthserver.lib.php';
require_once DOL_DOCUMENT_ROOT.'/oauthserver/class/oauthserverclient.class.php';

/**
 * @var Conf $conf
 * @var DoliDB $db
 * @var Translate $langs
 * @var User $user
 */

$langs->loadLangs(['admin', 'oauthserver']);

if (!$user->admin || !isModEnabled('oauthserver')) {
	accessforbidden();
}

$search_type = GETPOST('search_type', 'aZ09');
if (!in_array($search_type, ['admin', 'dynamic'], true)) {
	$search_type = '';
}

$limit = GETPOSTINT('limit') ? GETPOSTINT('limit') : $conf->liste_limit;
$page = GETPOSTISSET('pageplusone') ? (GETPOSTINT('pageplusone') - 1) : GETPOSTINT('page');
if (empty($page) || $page < 0 || GETPOST('button_search', 'alpha')) {
	$page = 0;
}
$offset = $limit * $page;


/*
 * View
 */

$title = $langs->trans("OAuthServerSetup");
llxHeader('', $langs->trans("OAuthClients"), '', '', 0, 0, '', '', '', 'mod-oauthserver page-client_list');

print load_fiche_titre($title, '', 'title_setup');
print dol_get_fiche_head(oauthserverAdminPrepareHead(), 'clients', $title, -1, 'technic');

$sqlwhere = " WHERE entity = ".((int) $conf->entity);
if ($search_type !== '') {
	$sqlwhere .= " AND registration_type = '".$db->escape($search_type)."'";
}

// Count the records, to show the number of pages
$nbtotalofrecords = '';
if (!getDolGlobalInt('MAIN_DISABLE_FULL_SCANLIST')) {
	$resql = $db->query("SELECT COUNT(rowid) as nb FROM ".$db->prefix()."oauth_client".$sqlwhere);
	$obj = ($resql ? $db->fetch_object($resql) : null);
	$nbtotalofrecords = ($obj ? (int) $obj->nb : 0);
	if (($page * $limit) > $nbtotalofrecords) {	// The filter reduced the list below the current page: go back to page 0
		$page = 0;
		$offset = 0;
	}
}

$sql = "SELECT rowid, label, client_id, registration_type, token_endpoint_auth_method, allowed_scopes, date_last_use, status";
$sql .= " FROM ".$db->prefix()."oauth_client";
$sql .= $sqlwhere;
$sql .= $db->order('label', 'ASC');
if ($limit) {
	$sql .= $db->plimit($limit + 1, $offset);
}
$resql = $db->query($sql);
if (!$resql) {
	dol_print_error($db);
}
$num = ($resql ? $db->num_rows($resql) : 0);

$param = '';
if ($search_type !== '') {
	$param .= '&search_type='.urlencode($search_type);
}
if ($limit > 0 && $limit != $conf->liste_limit) {
	$param .= '&limit='.((int) $limit);
}

print '<form method="GET" action="'.$_SERVER["PHP_SELF"].'">';
print '<input type="hidden" name="page" value="'.((int) $page).'">';

$morehtmlcenter = '<select name="search_type" class="flat">';
foreach (['' => $langs->trans("All"), 'admin' => $langs->trans("OAuthRegistrationAdmin"), 'dynamic' => $langs->trans("OAuthRegistrationDynamic")] as $key => $label) {
	$morehtmlcenter .= '<option value="'.$key.'"'.($search_type === $key ? ' selected' : '').'>'.dol_escape_htmltag($label).'</option>';
}
$morehtmlcenter .= '</select> <input type="submit" name="button_search" class="button small" value="'.dolPrintHTMLForAttribute($langs->trans("Search")).'">';

print_barre_liste($langs->trans("OAuthClients"), $page, $_SERVER["PHP_SELF"], $param, '', '', $morehtmlcenter, $num, $nbtotalofrecords, 'technic', 0, '', '', $limit, 0, 0, 1);

print '<div class="div-table-responsive"><table class="noborder centpercent">';
print '<tr class="liste_titre">';
print '<td>'.$langs->trans("Label").'</td><td>'.$langs->trans("OAuthClientId").'</td><td>'.$langs->trans("OAuthRegistration").'</td>';
print '<td>'.$langs->trans("OAuthAuthMethod").'</td><td>'.$langs->trans("OAuthAllowedScopes").'</td><td>'.$langs->trans("OAuthLastUse").'</td><td class="right">'.$langs->trans("Status").'</td>';
print '</tr>';

$i = 0;
$client = new OAuthServerClient($db);	// One object reused for getNomUrl() and getLibStatut(), filled from each row
while ($resql && $i < min($num, $limit) && ($obj = $db->fetch_object($resql))) {
	$i++;
	$client->id = (int) $obj->rowid;
	$client->label = (string) $obj->label;
	$client->status = (int) $obj->status;
	$datelastuse = ($obj->date_last_use ? $db->jdate($obj->date_last_use) : '');
	print '<tr class="oddeven">';
	print '<td>'.$client->getNomUrl(1).'</td>';
	print '<td>'.showValueWithClipboardCPButton((string) $obj->client_id, 1).'</td>';
	print '<td>'.($obj->registration_type === 'dynamic' ? '<span class="badge badge-warning">'.$langs->trans("OAuthRegistrationDynamic").'</span>' : $langs->trans("OAuthRegistrationAdmin")).'</td>';
	print '<td>'.dol_escape_htmltag($obj->token_endpoint_auth_method).'</td>';
	print '<td>'.dol_escape_htmltag($obj->allowed_scopes).'</td>';
	print '<td>'.($datelastuse ? dol_print_date($datelastuse, 'dayhour') : '').'</td>';
	print '<td class="right">'.$client->getLibStatut(5).'</td>';
	print '</tr>';
}
if ($num == 0) {
	print '<tr class="oddeven"><td colspan="7"><span class="opacitymedium">'.$langs->trans("None").'</span></td></tr>';
}
print '</table></div>';
print '</form>';

print '<div class="tabsAction"><a class="butAction" href="'.DOL_URL_ROOT.'/oauthserver/client_card.php?action=create">'.$langs->trans("OAuthNewClient").'</a></div>';

print dol_get_fiche_end();

llxFooter();
$db->close();
