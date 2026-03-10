// ─── ctrlTAB i18n ─────────────────────────────────────────────────────────────
// Lightweight translation system. No external dependencies.
// Usage: t('key')  or  t('key', { name: 'Work' })  for interpolation.
// Language is auto-detected from browser; user can override in Settings.
// ──────────────────────────────────────────────────────────────────────────────

const TRANSLATIONS = {

  en: {
    // ── Navigation ──────────────────────────────────────────────
    'nav.subtitle':                      'Link Manager',
    'nav.collections_label':             'Collections',
    'nav.search_placeholder':            'Search links...',
    'nav.search_clear':                  'Clear search',
    'nav.settings':                      'Settings',
    'nav.home_tooltip':                  'Go to last collection',

    // ── Collections ─────────────────────────────────────────────
    'btn.add_collection':                'Add Collection',
    'collection.edit':                   'Edit collection',
    'collection.empty':                  'Create your first collection',
    'collection.empty_btn':              'New Collection',
    'modal.add_collection':              'Add Collection',
    'modal.edit_collection':             'Edit Collection',
    'modal.delete_collection':           'Delete Collection',
    'confirm.delete_collection':         'Are you sure you want to delete "{name}"?',
    'confirm.delete_collection_warning': 'This will permanently delete all sections and links in this collection.',
    'error.create_collection':           'Failed to create collection',
    'error.update_collection':           'Failed to update collection',
    'error.delete_collection':           'Failed to delete collection',
    'error.load_collection':             'Failed to load collection',
    'form.collection_name_placeholder':  'e.g., Work Projects',

    // ── Sections ────────────────────────────────────────────────
    'btn.add_section':                   'Add Section',
    'section.empty':                     'No sections yet. Click "Add Section" to get started.',
    'section.edit':                      'Edit section',
    'modal.add_section':                 'Add Section',
    'modal.edit_section':                'Edit Section',
    'modal.delete_section':              'Delete Section',
    'confirm.delete_section':            'Are you sure you want to delete this section?',
    'confirm.delete_section_warning':    'This will permanently delete all links in this section.',
    'error.create_section':              'Failed to create section',
    'error.update_section':              'Failed to update section',
    'error.delete_section':              'Failed to delete section',
    'form.section_name_placeholder':     'e.g., Documentation',

    // ── Links ───────────────────────────────────────────────────
    'btn.add_link':                      'Add link',
    'btn.sort_alpha':                    'Sort A-Z',
    'btn.edit_link':                     'Edit link',
    'btn.copy_url':                      'Copy URL',
    'link.empty':                        'No links yet',
    'modal.add_link':                    'Add Link',
    'modal.edit_link':                   'Edit Link',
    'modal.delete_link':                 'Delete Link',
    'confirm.delete_link':               'Are you sure you want to delete this link?',
    'error.create_link':                 'Failed to create link',
    'error.update_link':                 'Failed to update link',
    'error.delete_link':                 'Failed to delete link',
    'form.link_title_placeholder':       'e.g., GitHub',
    'form.link_url_placeholder':         'https://github.com',
    'form.icon_label':                   'Icon (optional)',
    'form.icon_hint':                    'PNG, SVG or ICO \u00b7 max 2 MB',
    'btn.upload_icon':                   'Upload icon',

    // ── Shared form ─────────────────────────────────────────────
    'form.name_label':                   'Name',
    'form.title_label':                  'Title',
    'form.url_label':                    'URL',
    'btn.cancel':                        'Cancel',
    'btn.create':                        'Create',
    'btn.save':                          'Save',
    'btn.delete':                        'Delete',
    'btn.remove':                        'Remove',
    'btn.back':                          'Back',

    // ── Settings — general ──────────────────────────────────────
    'settings.title':                    'Settings',
    'settings.theme':                    'Theme',
    'settings.preferences':              'Preferences',
    'settings.account':                  'Account',
    'settings.data':                     'Data',
    'settings.language':                 'Language',

    // ── Settings — themes ───────────────────────────────────────
    'theme.light':                       'Light',
    'theme.dark':                        'Dark',
    'theme.oled':                        'OLED',
    'theme.cyberpunk':                   'Cyberpunk',
    'theme.batman':                      'Batman',

    // ── Settings — background ───────────────────────────────────
    'settings.background_image':         'Background image',
    'settings.no_background':            'No background set',
    'settings.dim_background':           'Dim background',
    'btn.upload_bg':                     'Upload',
    'btn.change_bg':                     'Change',

    // ── Settings — accent color ─────────────────────────────────
    'settings.accent_color':             'Accent color',
    'settings.custom_color':             'Custom color',

    // ── Settings — preferences ──────────────────────────────────
    'pref.open_new_tab':                 'Open links in new tab',
    'pref.show_url':                     'Show URL in link cards',
    'pref.two_col':                      'Two-column section layout',

    // ── Settings — user management ──────────────────────────────
    'admin.user_management':             'User Management',
    'admin.loading_users':               'Loading users...',
    'admin.col_username':                'Username',
    'admin.col_role':                    'Role',
    'admin.col_created':                 'Created',
    'admin.col_actions':                 'Actions',
    'btn.add_user':                      'Add User',
    'btn.edit_user':                     'Edit',
    'btn.delete_user':                   'Delete',
    'modal.add_user':                    'Add User',
    'modal.edit_user':                   'Edit User',
    'modal.delete_user':                 'Delete User',
    'confirm.delete_user':               'Are you sure you want to delete "{name}"?',
    'confirm.delete_user_warning':       'This will permanently delete all their collections, sections, and links.',
    'form.password_label':               'Password',
    'form.new_password_optional':        'New Password (leave empty to keep current)',
    'form.password_hint':                'Minimum 6 characters',
    'form.admin_privileges':             'Admin privileges',
    'btn.create_user':                   'Create User',
    'error.load_users':                  'Failed to load users',
    'error.create_user':                 'Failed to create user',
    'error.load_user':                   'Failed to load user',
    'error.update_user':                 'Failed to update user',
    'error.delete_user':                 'Failed to delete user',

    // ── Settings — account ──────────────────────────────────────
    'account.username':                  'Username',
    'account.role':                      'Role',
    'account.role_admin':                'Admin',
    'account.role_user':                 'User',
    'btn.change_password':               'Change Password',
    'btn.logout':                        'Logout',

    // ── Settings — data / import ────────────────────────────────
    'import.linkwarden_title':           'Import from Linkwarden',
    'import.linkwarden_hint':            'Upload a Linkwarden JSON export file. Each collection will be imported with one section (\u201cLinks\u201d).',
    'btn.choose_file':                   'Choose file',
    'import.importing':                  'Importing\u2026',
    'import.success':                    '\u2713 Imported {collections} collection{c_plural}, {links} link{l_plural}.',
    'import.failed':                     'Import failed.',

    // ── Settings — footer ───────────────────────────────────────
    'footer.credits':                    'Built by Michael Smith, with Claude Code',

    // ── Change password modal ───────────────────────────────────
    'modal.change_password':             'Change Password',
    'form.current_password':             'Current Password',
    'form.new_password':                 'New Password',
    'form.confirm_password':             'Confirm New Password',
    'error.password_mismatch':           'New passwords do not match',
    'success.password_changed':          'Password changed successfully',
    'error.change_password':             'Failed to change password',

    // ── Search ──────────────────────────────────────────────────
    'search.title':                      'Search: \u201c{query}\u201d',
    'search.no_results':                 'No results for \u201c{query}\u201d',
    'search.result_count':               '{n} result{plural}',

    // ── Login ───────────────────────────────────────────────────
    'login.subtitle':                    'Link Manager',
    'login.username':                    'Username',
    'login.password':                    'Password',
    'btn.login':                         'Login',
    'error.login_failed':                'Login failed',
  },

  // ─────────────────────────────────────────────────────────────
  nl: {
    // ── Navigatie ────────────────────────────────────────────────
    'nav.subtitle':                      'Link Manager',
    'nav.collections_label':             'Collecties',
    'nav.search_placeholder':            'Links zoeken\u2026',
    'nav.search_clear':                  'Zoekopdracht wissen',
    'nav.settings':                      'Instellingen',
    'nav.home_tooltip':                  'Ga naar laatste collectie',

    // ── Collecties ───────────────────────────────────────────────
    'btn.add_collection':                'Collectie toevoegen',
    'collection.edit':                   'Collectie bewerken',
    'collection.empty':                  'Maak je eerste collectie aan',
    'collection.empty_btn':              'Nieuwe collectie',
    'modal.add_collection':              'Collectie toevoegen',
    'modal.edit_collection':             'Collectie bewerken',
    'modal.delete_collection':           'Collectie verwijderen',
    'confirm.delete_collection':         'Weet je zeker dat je \u201c{name}\u201d wilt verwijderen?',
    'confirm.delete_collection_warning': 'Dit verwijdert permanent alle secties en links in deze collectie.',
    'error.create_collection':           'Kan collectie niet aanmaken',
    'error.update_collection':           'Kan collectie niet bijwerken',
    'error.delete_collection':           'Kan collectie niet verwijderen',
    'error.load_collection':             'Kan collectie niet laden',
    'form.collection_name_placeholder':  'bijv. Werkprojecten',

    // ── Secties ──────────────────────────────────────────────────
    'btn.add_section':                   'Sectie toevoegen',
    'section.empty':                     'Nog geen secties. Klik op \u201cSectie toevoegen\u201d om te beginnen.',
    'section.edit':                      'Sectie bewerken',
    'modal.add_section':                 'Sectie toevoegen',
    'modal.edit_section':                'Sectie bewerken',
    'modal.delete_section':              'Sectie verwijderen',
    'confirm.delete_section':            'Weet je zeker dat je deze sectie wilt verwijderen?',
    'confirm.delete_section_warning':    'Dit verwijdert permanent alle links in deze sectie.',
    'error.create_section':              'Kan sectie niet aanmaken',
    'error.update_section':              'Kan sectie niet bijwerken',
    'error.delete_section':              'Kan sectie niet verwijderen',
    'form.section_name_placeholder':     'bijv. Documentatie',

    // ── Links ────────────────────────────────────────────────────
    'btn.add_link':                      'Link toevoegen',
    'btn.sort_alpha':                    'Sorteren A-Z',
    'btn.edit_link':                     'Link bewerken',
    'btn.copy_url':                      'URL kopi\u00ebren',
    'link.empty':                        'Nog geen links',
    'modal.add_link':                    'Link toevoegen',
    'modal.edit_link':                   'Link bewerken',
    'modal.delete_link':                 'Link verwijderen',
    'confirm.delete_link':               'Weet je zeker dat je deze link wilt verwijderen?',
    'error.create_link':                 'Kan link niet aanmaken',
    'error.update_link':                 'Kan link niet bijwerken',
    'error.delete_link':                 'Kan link niet verwijderen',
    'form.link_title_placeholder':       'bijv. GitHub',
    'form.link_url_placeholder':         'https://github.com',
    'form.icon_label':                   'Pictogram (optioneel)',
    'form.icon_hint':                    'PNG, SVG of ICO \u00b7 max 2 MB',
    'btn.upload_icon':                   'Pictogram uploaden',

    // ── Gedeeld formulier ────────────────────────────────────────
    'form.name_label':                   'Naam',
    'form.title_label':                  'Titel',
    'form.url_label':                    'URL',
    'btn.cancel':                        'Annuleren',
    'btn.create':                        'Aanmaken',
    'btn.save':                          'Opslaan',
    'btn.delete':                        'Verwijderen',
    'btn.remove':                        'Verwijderen',
    'btn.back':                          'Terug',

    // ── Instellingen — algemeen ──────────────────────────────────
    'settings.title':                    'Instellingen',
    'settings.theme':                    'Thema',
    'settings.preferences':              'Voorkeuren',
    'settings.account':                  'Account',
    'settings.data':                     'Gegevens',
    'settings.language':                 'Taal',

    // ── Instellingen — thema's ───────────────────────────────────
    'theme.light':                       'Licht',
    'theme.dark':                        'Donker',
    'theme.oled':                        'OLED',
    'theme.cyberpunk':                   'Cyberpunk',
    'theme.batman':                      'Batman',

    // ── Instellingen — achtergrond ───────────────────────────────
    'settings.background_image':         'Achtergrondafbeelding',
    'settings.no_background':            'Geen achtergrond ingesteld',
    'settings.dim_background':           'Achtergrond dimmen',
    'btn.upload_bg':                     'Uploaden',
    'btn.change_bg':                     'Wijzigen',

    // ── Instellingen — accentkleur ───────────────────────────────
    'settings.accent_color':             'Accentkleur',
    'settings.custom_color':             'Aangepaste kleur',

    // ── Instellingen — voorkeuren ────────────────────────────────
    'pref.open_new_tab':                 'Links openen in nieuw tabblad',
    'pref.show_url':                     'URL tonen in linkaarten',
    'pref.two_col':                      'Indeling met twee kolommen',

    // ── Instellingen — gebruikersbeheer ──────────────────────────
    'admin.user_management':             'Gebruikersbeheer',
    'admin.loading_users':               'Gebruikers laden\u2026',
    'admin.col_username':                'Gebruikersnaam',
    'admin.col_role':                    'Rol',
    'admin.col_created':                 'Aangemaakt',
    'admin.col_actions':                 'Acties',
    'btn.add_user':                      'Gebruiker toevoegen',
    'btn.edit_user':                     'Bewerken',
    'btn.delete_user':                   'Verwijderen',
    'modal.add_user':                    'Gebruiker toevoegen',
    'modal.edit_user':                   'Gebruiker bewerken',
    'modal.delete_user':                 'Gebruiker verwijderen',
    'confirm.delete_user':               'Weet je zeker dat je \u201c{name}\u201d wilt verwijderen?',
    'confirm.delete_user_warning':       'Dit verwijdert permanent al hun collecties, secties en links.',
    'form.password_label':               'Wachtwoord',
    'form.new_password_optional':        'Nieuw wachtwoord (leeg laten om huidig te behouden)',
    'form.password_hint':                'Minimaal 6 tekens',
    'form.admin_privileges':             'Beheerdersrechten',
    'btn.create_user':                   'Gebruiker aanmaken',
    'error.load_users':                  'Kan gebruikers niet laden',
    'error.create_user':                 'Kan gebruiker niet aanmaken',
    'error.load_user':                   'Kan gebruiker niet laden',
    'error.update_user':                 'Kan gebruiker niet bijwerken',
    'error.delete_user':                 'Kan gebruiker niet verwijderen',

    // ── Instellingen — account ───────────────────────────────────
    'account.username':                  'Gebruikersnaam',
    'account.role':                      'Rol',
    'account.role_admin':                'Beheerder',
    'account.role_user':                 'Gebruiker',
    'btn.change_password':               'Wachtwoord wijzigen',
    'btn.logout':                        'Afmelden',

    // ── Instellingen — gegevens / import ─────────────────────────
    'import.linkwarden_title':           'Importeren uit Linkwarden',
    'import.linkwarden_hint':            'Upload een Linkwarden JSON-exportbestand. Elke collectie wordt ge\u00efmporteerd met \u00e9\u00e9n sectie (\u201cLinks\u201d).',
    'btn.choose_file':                   'Bestand kiezen',
    'import.importing':                  'Importeren\u2026',
    'import.success':                    '\u2713 {collections} collectie{c_plural} en {links} link{l_plural} ge\u00efmporteerd.',
    'import.failed':                     'Importeren mislukt.',

    // ── Instellingen — footer ────────────────────────────────────
    'footer.credits':                    'Built by Michael Smith, with Claude Code',

    // ── Wachtwoord wijzigen ──────────────────────────────────────
    'modal.change_password':             'Wachtwoord wijzigen',
    'form.current_password':             'Huidig wachtwoord',
    'form.new_password':                 'Nieuw wachtwoord',
    'form.confirm_password':             'Nieuw wachtwoord bevestigen',
    'error.password_mismatch':           'Nieuwe wachtwoorden komen niet overeen',
    'success.password_changed':          'Wachtwoord succesvol gewijzigd',
    'error.change_password':             'Kan wachtwoord niet wijzigen',

    // ── Zoeken ───────────────────────────────────────────────────
    'search.title':                      'Zoeken: \u201c{query}\u201d',
    'search.no_results':                 'Geen resultaten voor \u201c{query}\u201d',
    'search.result_count':               '{n} resultaat{plural}',

    // ── Inloggen ─────────────────────────────────────────────────
    'login.subtitle':                    'Link Manager',
    'login.username':                    'Gebruikersnaam',
    'login.password':                    'Wachtwoord',
    'btn.login':                         'Inloggen',
    'error.login_failed':                'Inloggen mislukt',
  },
};

// ── Core ──────────────────────────────────────────────────────────────────────

let _lang = 'en';

function detectLang() {
  const saved = localStorage.getItem('ctrltab-lang');
  if (saved === 'nl' || saved === 'en') return saved;
  return navigator.language?.toLowerCase().startsWith('nl') ? 'nl' : 'en';
}

/**
 * Translate a key, with optional variable interpolation.
 * t('confirm.delete_collection', { name: 'Work' })
 * Falls back to English, then to the key itself.
 */
function t(key, vars) {
  let str = TRANSLATIONS[_lang]?.[key] ?? TRANSLATIONS.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      str = str.replaceAll(`{${k}}`, v);
    }
  }
  return str;
}
