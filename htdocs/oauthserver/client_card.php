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
 * \file    htdocs/oauthserver/client_card.php
 * \ingroup oauthserver
 * \brief   Card of a client application of the OAuth server
 */

// Load Dolibarr environment
require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.form.class.php';
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

$id = GETPOSTINT('id');
$action = GETPOST('action', 'aZ09');
$confirm = GETPOST('confirm', 'alpha');
$cancel = GETPOST('cancel', 'alpha');

$permissiontoadd = $user->admin;
$permissiontodelete = $user->admin;

$object = new OAuthServerClient($db);
if ($id > 0) {
	if ($object->fetch($id) <= 0 || (int) $object->entity !== (int) $conf->entity) {
		accessforbidden();
	}
}

/**
 * Read the form fields into the client.
 *
 * @param	OAuthServerClient	$object		Client to fill
 * @return	void
 */
function oauthserverClientFromPost($object)
{
	$object->label = GETPOST('label', 'alphanohtml');
	$object->redirect_uris = preg_split('/\R/', GETPOST('redirect_uris', 'alphanohtml'), -1, PREG_SPLIT_NO_EMPTY) ?: [];
	$scopes = GETPOST('allowed_scopes', 'array:aZ09');
	$object->allowed_scopes = array_values(array_intersect(oauthserverGetSupportedScopes(), is_array($scopes) ? $scopes : []));
}


/*
 * Actions
 */

if ($cancel) {
	if ($id <= 0) {
		header("Location: ".DOL_URL_ROOT.'/oauthserver/client_list.php');
		exit;
	}
	$action = '';
}

if ($action == 'add' && $permissiontoadd) {
	oauthserverClientFromPost($object);
	$object->token_endpoint_auth_method = GETPOST('token_endpoint_auth_method', 'aZ09');
	$object->registration_type = 'admin';
	if ($object->create($user) > 0) {
		if ($object->client_secret_plain !== '') {
			$_SESSION['oauthserver_newsecret_'.$object->id] = $object->client_secret_plain;
		}
		header("Location: ".$_SERVER["PHP_SELF"].'?id='.((int) $object->id));
		exit;
	}
	setEventMessages($langs->trans($object->error), $object->errors, 'errors');
	$action = 'create';
}

if ($action == 'update' && $permissiontoadd && $object->id > 0) {
	oauthserverClientFromPost($object);
	if ($object->update($user) > 0) {
		header("Location: ".$_SERVER["PHP_SELF"].'?id='.((int) $object->id));
		exit;
	}
	setEventMessages($langs->trans($object->error), $object->errors, 'errors');
	$action = 'edit';
}

if (($action == 'enable' || $action == 'disable') && $permissiontoadd && $object->id > 0) {
	$newstatus = ($action == 'enable' && $permissiontoadd ? OAuthServerClient::STATUS_ENABLED : OAuthServerClient::STATUS_DISABLED);
	if ($object->setStatus($user, $newstatus) < 0) {
		setEventMessages($langs->trans($object->error), $object->errors, 'errors');
	}
	$action = '';
}

if ($action == 'confirm_delete' && $confirm == 'yes' && $permissiontodelete && $object->id > 0) {
	if ($object->delete($user) > 0) {
		header("Location: ".DOL_URL_ROOT.'/oauthserver/client_list.php');
		exit;
	}
	setEventMessages($object->error, $object->errors, 'errors');
}


/*
 * View
 */

$form = new Form($db);
$title = $langs->trans("OAuthClient");
llxHeader('', $title, '', '', 0, 0, '', '', '', 'mod-oauthserver page-client_card');

print load_fiche_titre($langs->trans("OAuthServerSetup"), '', 'title_setup');
print dol_get_fiche_head(oauthserverAdminPrepareHead(), 'clients', $langs->trans("OAuthServerSetup"), -1, 'technic');

if ($action == 'delete') {
	print $form->formconfirm($_SERVER["PHP_SELF"].'?id='.((int) $object->id), $langs->trans("OAuthDeleteClient"), $langs->trans("OAuthConfirmDeleteClient"), 'confirm_delete', '', 0, 1);
}

if ($action == 'create' || $action == 'edit') {
	print '<form method="POST" action="'.$_SERVER["PHP_SELF"].'">';
	print '<input type="hidden" name="token" value="'.newToken().'">';
	print '<input type="hidden" name="action" value="'.($action == 'create' ? 'add' : 'update').'">';
	print '<input type="hidden" name="id" value="'.((int) $object->id).'">';
	print '<table class="border centpercent tableforfieldcreate">';
	print '<tr><td class="titlefieldcreate fieldrequired">'.$langs->trans("Label").'</td><td><input type="text" class="minwidth300" name="label" value="'.dolPrintHTMLForAttribute($object->label).'"></td></tr>';
	print '<tr><td class="fieldrequired">'.$form->textwithpicto($langs->trans("OAuthRedirectUris"), $langs->trans("OAuthRedirectUrisHelp")).'</td>';
	print '<td><textarea name="redirect_uris" class="quatrevingtpercent" rows="3">'.dol_escape_htmltag(implode("\n", $object->redirect_uris)).'</textarea></td></tr>';
	if ($action == 'create') {
		print '<tr><td>'.$form->textwithpicto($langs->trans("OAuthAuthMethod"), $langs->trans("OAuthAuthMethodHelp")).'</td><td>';
		print $form->selectarray('token_endpoint_auth_method', [
			'none' => $langs->trans("OAuthAuthMethodNone"),
			'client_secret_basic' => $langs->trans("OAuthAuthMethodBasic"),
			'client_secret_post' => $langs->trans("OAuthAuthMethodPost"),
		], $object->token_endpoint_auth_method);
		print '</td></tr>';
	}
	print '<tr><td class="fieldrequired">'.$langs->trans("OAuthAllowedScopes").'</td><td>';
	foreach (oauthserverGetSupportedScopes() as $scope) {
		$checked = ($action == 'create' && empty($object->allowed_scopes)) ? ($scope !== 'write') : in_array($scope, $object->allowed_scopes, true);
		print '<label class="paddingright"><input type="checkbox" name="allowed_scopes[]" value="'.$scope.'"'.($checked ? ' checked' : '').'> '.$scope.'</label> ';
	}
	print '</td></tr>';
	print '</table>';
	print $form->buttonsSaveCancel($action == 'create' ? 'Create' : 'Save');
	print '</form>';
} elseif ($object->id > 0) {
	$secretkey = 'oauthserver_newsecret_'.$object->id;
	if (!empty($_SESSION[$secretkey])) {
		print info_admin($langs->trans("OAuthSecretShownOnce").'<br><br>'.showValueWithClipboardCPButton((string) $_SESSION[$secretkey], 0), 0, 0, 'warning');
		unset($_SESSION[$secretkey]);
	}

	print '<table class="border centpercent tableforfield">';
	print '<tr><td class="titlefield">'.$langs->trans("Label").'</td><td>'.dol_escape_htmltag($object->label).'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthClientId").'</td><td>'.showValueWithClipboardCPButton($object->client_id, 0).'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthRedirectUris").'</td><td>'.implode('<br>', array_map('dol_escape_htmltag', $object->redirect_uris)).'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthAuthMethod").'</td><td>'.dol_escape_htmltag($object->token_endpoint_auth_method).'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthAllowedScopes").'</td><td>'.dol_escape_htmltag(implode(' ', $object->allowed_scopes)).'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthRegistration").'</td><td>'.($object->registration_type === 'dynamic' ? '<span class="badge badge-warning">'.$langs->trans("OAuthRegistrationDynamic").'</span>' : $langs->trans("OAuthRegistrationAdmin")).'</td></tr>';
	print '<tr><td>'.$langs->trans("DateCreation").'</td><td>'.dol_print_date($object->datec, 'dayhour').'</td></tr>';
	print '<tr><td>'.$langs->trans("OAuthLastUse").'</td><td>'.($object->date_last_use ? dol_print_date($object->date_last_use, 'dayhour') : '').'</td></tr>';
	print '<tr><td>'.$langs->trans("Status").'</td><td>'.$object->getLibStatut(4).'</td></tr>';
	print '</table>';

	print '<div class="tabsAction">';
	print '<a class="butAction" href="'.$_SERVER["PHP_SELF"].'?id='.((int) $object->id).'&action=edit&token='.newToken().'">'.$langs->trans("Modify").'</a>';
	if ((int) $object->status === OAuthServerClient::STATUS_ENABLED) {
		print '<a class="butAction" href="'.$_SERVER["PHP_SELF"].'?id='.((int) $object->id).'&action=disable&token='.newToken().'">'.$langs->trans("Disable").'</a>';
	} else {
		print '<a class="butAction" href="'.$_SERVER["PHP_SELF"].'?id='.((int) $object->id).'&action=enable&token='.newToken().'">'.$langs->trans("Enable").'</a>';
	}
	print '<a class="butActionDelete" href="'.$_SERVER["PHP_SELF"].'?id='.((int) $object->id).'&action=delete&token='.newToken().'">'.$langs->trans("Delete").'</a>';
	print '</div>';
}

print dol_get_fiche_end();

llxFooter();
$db->close();
