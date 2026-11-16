"""Unit tests for internationalization (i18n) browser Accept-Language detection and 9 supported languages."""

import pytest
from flask import session
from embervault_app.factory import create_app
from embervault_app.i18n import SUPPORTED_LOCALES, translate, get_current_locale


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-i18n"
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_supported_locales_count():
    """Verify that all required 9 languages are registered."""
    expected = {"it", "en", "de", "es", "fr", "zh", "ja", "ko", "ar"}
    assert set(SUPPORTED_LOCALES) == expected


@pytest.mark.parametrize(
    "accept_language,expected_locale",
    [
        ("de-DE,de;q=0.9,en;q=0.8", "de"),
        ("es-ES,es;q=0.9,en;q=0.8", "es"),
        ("fr-FR,fr;q=0.9,en;q=0.8", "fr"),
        ("zh-CN,zh;q=0.9,en;q=0.8", "zh"),
        ("ja-JP,ja;q=0.9,en;q=0.8", "ja"),
        ("ko-KR,ko;q=0.9,en;q=0.8", "ko"),
        ("ar-SA,ar;q=0.9,en;q=0.8", "ar"),
        ("en-US,en;q=0.9", "en"),
        ("it-IT,it;q=0.9", "it"),
        ("pl-PL,pl;q=0.9", "en"),  # unsupported language defaults to English
    ],
)
def test_browser_accept_language_detection(app, accept_language, expected_locale):
    """Verify that when no explicit language preference is set, the browser's Accept-Language header is used."""
    with app.test_request_context("/", headers={"Accept-Language": accept_language}):
        detected = get_current_locale()
        assert detected == expected_locale


def test_query_param_overrides_browser_language(app):
    """Verify that ?lang= query param takes precedence over browser header and persists in session."""
    client = app.test_client()
    # Browser says German, but user explicitly asks for French
    response = client.get("/login?lang=fr", headers={"Accept-Language": "de-DE,de;q=0.9"})
    assert response.status_code == 200

    # Next request without ?lang= should retain 'fr' from session
    with client.session_transaction() as sess:
        assert sess.get("locale") == "fr"


def test_session_locale_precedence(app):
    """Verify that an explicit session locale overrides Accept-Language header."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["locale"] = "ja"

    # Make request with Spanish header, following redirects to rendered page
    response = client.get("/", headers={"Accept-Language": "es-ES,es;q=0.9"}, follow_redirects=True)
    assert response.status_code == 200
    # Check that template was rendered with Japanese
    assert b'lang="ja"' in response.data


def test_arabic_rtl_direction(app):
    """Verify that Arabic locale sets dir='rtl' on html root tag."""
    client = app.test_client()
    response = client.get("/", query_string={"lang": "ar"}, follow_redirects=True)
    assert response.status_code == 200
    assert b'dir="rtl"' in response.data

    # And non-Arabic sets dir='ltr'
    response_en = client.get("/", query_string={"lang": "en"}, follow_redirects=True)
    assert response_en.status_code == 200
    assert b'dir="ltr"' in response_en.data


@pytest.mark.parametrize(
    "locale,expected_nav_dashboard,expected_cancel",
    [
        ("it", "Dashboard", "Annulla"),
        ("en", "Dashboard", "Cancel"),
        ("de", "Dashboard", "Abbrechen"),
        ("es", "Panel de Control", "Cancelar"),
        ("fr", "Tableau de Bord", "Annuler"),
        ("zh", "仪表板", "取消"),
        ("ja", "ダッシュボード", "キャンセル"),
        ("ko", "대시보드", "취소"),
        ("ar", "لوحة التحكم", "إلغاء"),
    ],
)
def test_translations_coverage(app, locale, expected_nav_dashboard, expected_cancel):
    """Verify translation strings for each of the 9 languages."""
    with app.test_request_context("/", headers={"Accept-Language": locale}):
        assert translate("nav_dashboard") == expected_nav_dashboard
        assert translate("btn_cancel") == expected_cancel


def test_proxy_translations_coverage_all_locales(app):
    """Verify all 9 supported locales have complete proxy translations."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    keys_to_check = [
        "register_proxy_subtitle",
        "proxy_host_placeholder",
        "proxy_token_placeholder",
        "proxy_concurrency_label",
        "proxy_concurrency_desc",
        "proxy_enabled_active",
        "proxy_enabled_disabled",
        "proxy_new_token_label",
        "proxy_new_token_placeholder",
        "proxy_new_token_desc",
        "delete_proxy_confirm_text",
        "delete_proxy_warning",
    ]

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        for k in keys_to_check:
            assert k in catalog, f"Missing key {k} in locale {loc}"
            assert catalog[k], f"Empty value for key {k} in locale {loc}"


def test_remote_translations_coverage_all_locales(app):
    """Verify all 9 supported locales have complete remote & browse modal translations."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    remote_keys_to_check = [
        # Categories / Subtitles
        "Storage Locale & LAN",
        "Backend Speciale",
        "Object Storage",
        "Server Remoto",
        "Cloud / Storage",
        "Cloud Pubblico",
        "Storage",
        # Delete Modal
        "delete_remote_modal_title",
        "delete_remote_confirm_text",
        "delete_remote_warning_text",
        # Remote Edit Screen
        "btn_back_to_remotes",
        "remote_config_edit_title",
        "remote_config_create_title",
        "remote_envelope_encryption_notice",
        "remote_step1_select_provider",
        "remote_section_popular",
        "remote_section_other",
        "remote_badge_providers",
        "remote_expand",
        "remote_collapse",
        "remote_search_placeholder",
        "remote_no_backends_found",
        "remote_section_special",
        "remote_badge_backends",
        "remote_provider_type_label",
        "remote_name_label",
        "remote_name_placeholder",
        "remote_name_hint",
        "remote_connection_params_title",
        "remote_none_available",
        "remote_subpath_placeholder",
        "remote_enable_option",
        "remote_keep_secret_hint",
        "remote_testing_connection",
        "remote_test_success_title",
        "remote_test_success_msg",
        "remote_response_time",
        "remote_test_failed_title",
        "remote_test_failed_msg",
        "remote_network_error_prefix",
        "remote_saving",
        "btn_test_connection_now",
        "btn_browse_remote",
        "btn_create_remote",
        # Browse Modal
        "modal_browse_title",
        "browse_current_path_label",
        "browse_current_path_title",
        "browse_copy_path_title",
        "btn_copy",
        "btn_copied",
        "browse_parent_level_title",
        "browse_parent_level_text",
        "browse_loading_text",
        "browse_modal_hint",
        "browse_error_loading",
        "browse_no_data_error",
        "browse_folders_count",
        "browse_files_count",
        "browse_empty_folder",
        "browse_open_folder",
        "browse_file_badge",
        "browse_connection_failed",
        "browse_copy_failed",
        # Verification modal & button
        "btn_verifying",
        "test_connection_result_modal_title",
        "remote_test_result_title",
        "remote_operational_reachable",
        "latency_label",
        "items_found_label",
        "network_error_title",
        "test_request_error",
        "configure_first_remote",
        # Backend labels & descriptions
        "Disco Locale / Mount Point",
        "File system locale o punto di montaggio NFS/iSCSI visibile ai proxy.",
        "SMB / CIFS (Windows Share)",
        "HTTP Server (Read-Only)",
        "Crypt (Crittografia)",
        "Compress (Compressione)",
        "Chunker (Suddivisione)",
        "Union (Aggregazione)",
        # Field labels (specifically requested: Regione, Classe di Storage, etc.)
        "Regione",
        "Classe di Storage",
        "Provider S3",
        "Host / Indirizzo IP",
        "Porta SSH",
        "Nome Utente",
        "Password",
        "Eliminazione definitiva (Hard Delete)",
        "Target Remote (es. remote:path)",
        "Remote Sottostante (es. remote:path)",
        "Password Principale",
        "Metodo di Compressione",
        "Dimensione Frammenti (Chunk Size)",
        # Field help texts (subtitles under textboxes)
        "Tipo specifico di implementazione S3.",
        "Obbligatorio per MinIO, Ceph, Wasabi o Cloudflare R2. Lasciare vuoto per AWS.",
        "Regione del bucket S3.",
        "Chiave di accesso o username API.",
        "Chiave segreta di accesso S3.",
        "Controllo accessi applicato ai nuovi oggetti caricati.",
        "Classe di storage di destinazione.",
        "Identificativo Application Key generato dalla console Backblaze.",
        "Chiave segreta generata dalla console Backblaze.",
        "Se abilitato, elimina definitivamente i file anziché creare versioni nascoste.",
        "Nome host o indirizzo IPv4/IPv6 del server SFTP.",
        "Porta SSH (predefinita: 22).",
        "Utente Linux o SFTP remoto.",
        "Password di accesso (se non si utilizza chiave privata).",
        "Incolla qui la chiave privata SSH in formato OpenSSH o PEM.",
        "URL completo dell'endpoint WebDAV.",
        "Vendor del server WebDAV per ottimizzazioni di protocollo.",
        "Nome utente o username della password applicativa.",
        "Password dell'account o App Password generata su Nextcloud.",
        "Indirizzo IP o nome del server Windows / SAMBA.",
        "Nome utente con accesso alla share.",
        "Password di autenticazione SMB.",
        "Dominio Active Directory o Workgroup.",
        "Porta SMB (predefinita: 445).",
        "Se abilitato, segue i symlink copiando il file puntato.",
        "Mantiene i symlink salvandone il target come file speciale.",
        "Remote e percorso di destinazione a cui puntare",
        "Remote e percorso sottostante su cui salvare i dati cifrati",
        "Password usata per cifrare i dati",
        "Password secondaria opzionale usata come salt di sicurezza",
        "Modalità di offuscamento dei nomi dei file",
        "Se abilitato, anche i nomi delle cartelle vengono cifrati",
        "Remote e percorso sottostante su cui salvare i file compressi",
        "Algoritmo di compressione",
        "Remote e percorso sottostante per memorizzare i chunk",
        "Dimensione massima di ciascun frammento",
        "Pattern per i file frammentati",
        "Algoritmo di checksum tra i blocchi",
        "Elenco di remote/percorsi separati da spazio (es. s3-a:backup b2-b:backup)",
        # Select options
        "Altro compatibile S3",
        "Personale (OneDrive)",
        "Aziendale / Business",
        "Libreria Documenti SharePoint",
        "Offuscamento semplice",
        "Disattivata (nomi in chiaro)",
        # Remote verification & validation keys
        "remote_test_success_folders",
        "remote_test_success_single_folder",
        "remote_test_success_no_folders",
        "invalid_config_prefix",
        "error_field_required",
        "error_field_must_be_integer",
        "error_unsupported_backend",
    ]

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        for k in remote_keys_to_check:
            assert k in catalog, f"Missing key '{k}' in locale '{loc}'"
            assert catalog[k], f"Empty value for key '{k}' in locale '{loc}'"


def test_remote_error_and_success_localization(app):
    """Test that remote test success and validation error messages are localized for all locales."""
    from flask import g
    from embervault_app.blueprints.api import (
        _localize_remote_error,
        _localize_remote_success_message,
    )
    from embervault_common.remotes.catalog import RemoteConfigValidationError

    with app.test_request_context("/"):
        # Test Italian (it)
        g.locale = "it"
        succ_it = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert succ_it == "Connessione riuscita. 22 cartelle rilevate."

        err_exc = RemoteConfigValidationError(
            "Il campo obbligatorio 'Access Key ID' non è stato specificato.",
            field_name="access_key_id",
            field_label="Access Key ID",
            error_type="required",
        )
        err_it = _localize_remote_error(err_exc)
        assert "Configurazione non valida:" in err_it
        assert "Il campo obbligatorio 'Access Key ID' non è stato specificato." in err_it

        # Test string parsing fallback
        err_str_it = _localize_remote_error(
            "Configurazione non valida: Il campo obbligatorio 'Access Key ID' non è stato specificato."
        )
        assert "Configurazione non valida:" in err_str_it
        assert "Il campo obbligatorio 'Access Key ID' non è stato specificato." in err_str_it

        # Test English (en)
        g.locale = "en"
        succ_en = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert succ_en == "Connection successful. 22 folders detected."
        err_en = _localize_remote_error(err_exc)
        assert (
            err_en == "Invalid configuration: The required field 'Access Key ID' was not specified."
        )
        err_str_en = _localize_remote_error(
            "Configurazione non valida: Il campo obbligatorio 'Access Key ID' non è stato specificato."
        )
        assert (
            err_str_en
            == "Invalid configuration: The required field 'Access Key ID' was not specified."
        )

        # Test German (de)
        g.locale = "de"
        succ_de = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert "22 Ordner erkannt" in succ_de
        err_de = _localize_remote_error(err_exc)
        assert "Ungültige Konfiguration" in err_de
        assert "Access Key ID" in err_de

        # Test Spanish (es)
        g.locale = "es"
        succ_es = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert "22 carpetas detectadas" in succ_es
        err_es = _localize_remote_error(err_exc)
        assert "Configuración no válida" in err_es
        assert "Access Key ID" in err_es

        # Test French (fr)
        g.locale = "fr"
        succ_fr = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert "22 dossiers détectés" in succ_fr
        err_fr = _localize_remote_error(err_exc)
        assert "Configuration non valide" in err_fr
        assert "Access Key ID" in err_fr

        # Test Japanese (ja)
        g.locale = "ja"
        succ_ja = _localize_remote_success_message(
            "Connessione riuscita. 22 cartelle rilevate.", items_found=22
        )
        assert "22 個のフォルダーが検出されました" in succ_ja
        err_ja = _localize_remote_error(err_exc)
        assert "無効な構成" in err_ja
        assert "Access Key ID" in err_ja


def test_permissions_matrix_i18n_translations():
    """Verify that all permission categories, names, and descriptions are translated across all 9 locales."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    test_keys = [
        "Nodi Proxy",
        "Utenti & Ruoli",
        "Autenticazione",
        "Impostazioni & Sistema",
        "Visualizzazione",
        "Creazione",
        "Modifica",
        "Eliminazione",
        "Esecuzione",
        "Gestione Completa",
        "Visualizzazione configurazione, stato ed elenco delle esecuzioni dei job",
        "Administrator",
        "Operator",
        "Viewer",
    ]

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        for k in test_keys:
            assert k in catalog, f"Missing key '{k}' in locale '{loc}'"
            assert catalog[k], f"Empty translation for '{k}' in locale '{loc}'"

    # Specific locale assertions
    assert TRANSLATIONS["en"]["Nodi Proxy"] == "Proxy Nodes"
    assert TRANSLATIONS["en"]["Visualizzazione"] == "View"
    assert TRANSLATIONS["de"]["Nodi Proxy"] == "Proxy-Knoten"
    assert TRANSLATIONS["de"]["Visualizzazione"] == "Anzeigen"
    assert TRANSLATIONS["es"]["Nodi Proxy"] == "Nodos Proxy"
    assert TRANSLATIONS["es"]["Visualizzazione"] == "Ver"
    assert TRANSLATIONS["fr"]["Nodi Proxy"] == "Nœuds Proxy"
    assert TRANSLATIONS["fr"]["Visualizzazione"] == "Affichage"


def test_proxy_deactivate_active_tasks_warning_i18n():
    """Verify that proxy_deactivate_active_tasks_warning is translated across all 9 locales."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    key = "proxy_deactivate_active_tasks_warning"
    literal_key = (
        "Il Proxy selezionato sta eseguendo uno o più task. "
        "L'esecuzione non verrà arrestata, ma al Proxy non verranno più assegnati task."
    )

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        assert key in catalog, f"Missing key '{key}' in locale '{loc}'"
        assert catalog[key], f"Empty translation for '{key}' in locale '{loc}'"
        assert literal_key in catalog, f"Missing literal key in locale '{loc}'"
        assert catalog[literal_key], f"Empty literal translation in locale '{loc}'"

    # Specific locale validations
    assert "execution will not be stopped" in TRANSLATIONS["en"][key].lower()
    assert "nicht gestoppt" in TRANSLATIONS["de"][key]
    assert "no se detendrá" in TRANSLATIONS["es"][key]
    assert "ne sera pas arrêtée" in TRANSLATIONS["fr"][key]
    assert "执行不会停止" in TRANSLATIONS["zh"][key]
    assert "実行は停止されません" in TRANSLATIONS["ja"][key]
    assert "실행은 중단되지 않지만" in TRANSLATIONS["ko"][key]
    assert "لن يتم إيقاف التنفيذ" in TRANSLATIONS["ar"][key]


def test_job_browse_translations_coverage_all_locales():
    """Verify that all job remote browse translation keys exist and are non-empty across all 9 locales."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    browse_keys = [
        "btn_browse_remote",
        "browse_select_remote_first_tooltip",
        "browse_btn_use_current_path",
        "browse_btn_select_folder",
        "job_browse_title_source",
        "job_browse_title_destination",
        "job_browse_modal_hint",
        "job_browse_path_selected_toast",
    ]

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        for k in browse_keys:
            assert k in catalog, f"Missing key '{k}' in locale '{loc}'"
            assert catalog[k], f"Empty translation for '{k}' in locale '{loc}'"

    # Specific assertions
    assert TRANSLATIONS["it"]["btn_browse_remote"] == "Sfoglia..."
    assert TRANSLATIONS["en"]["btn_browse_remote"] == "Browse..."
    assert TRANSLATIONS["it"]["browse_btn_use_current_path"] == "Imposta questo percorso"
    assert TRANSLATIONS["en"]["browse_btn_use_current_path"] == "Set this path"
    assert TRANSLATIONS["de"]["browse_btn_use_current_path"] == "Diesen Pfad festlegen"
    assert TRANSLATIONS["es"]["browse_btn_use_current_path"] == "Establecer esta ruta"
    assert TRANSLATIONS["fr"]["browse_btn_use_current_path"] == "Définir ce chemin"
    assert TRANSLATIONS["zh"]["browse_btn_use_current_path"] == "设置此路径"
    assert TRANSLATIONS["ja"]["browse_btn_use_current_path"] == "このパスを設定"
    assert TRANSLATIONS["ko"]["browse_btn_use_current_path"] == "이 경로 설정"
    assert TRANSLATIONS["ar"]["browse_btn_use_current_path"] == "تعيين هذا المسار"


def test_job_schedule_timezone_dst_translations_coverage_all_locales():
    """Verify all 9 supported locales have complete translations for job schedule timezone and DST controls."""
    from embervault_app.i18n import SUPPORTED_LOCALES, TRANSLATIONS

    keys = [
        "job_schedule_timezone_label",
        "job_schedule_timezone_hint",
        "job_schedule_follow_dst_label",
        "job_schedule_follow_dst_hint",
        "api_err_invalid_timezone",
    ]

    for loc in SUPPORTED_LOCALES:
        catalog = TRANSLATIONS.get(loc, {})
        for k in keys:
            assert k in catalog, f"Missing key '{k}' in locale '{loc}'"
            assert catalog[k], f"Empty value for key '{k}' in locale '{loc}'"

    assert TRANSLATIONS["it"]["job_schedule_follow_dst_label"] == "Segui ora legale/solare"
    assert TRANSLATIONS["en"]["job_schedule_follow_dst_label"] == "Follow daylight saving time"
