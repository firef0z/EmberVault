"""Catalog of supported RClone backend providers, parameter schemas, and validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

FieldType = Literal["text", "password", "number", "boolean", "select", "textarea"]


@dataclass(frozen=True)
class BackendField:
    """Schema descriptor for a single backend configuration property."""

    name: str
    label: str
    type: FieldType
    required: bool = False
    is_secret: bool = False
    default: Any | None = None
    options: list[tuple[str, str]] = field(default_factory=list)  # (value, label) for select
    help_text: str = ""
    placeholder: str = ""


@dataclass(frozen=True)
class BackendSpec:
    """Metadata and field specifications for a supported RClone storage backend."""

    backend_type: str
    label: str
    category: str
    description: str
    icon: str  # Icon name or SVG indicator
    fields: list[BackendField]
    default_options: dict[str, Any] = field(default_factory=dict)
    is_popular: bool = False
    is_special: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert specification to JSON-serializable dictionary."""
        return {
            "backend_type": self.backend_type,
            "label": self.label,
            "category": self.category,
            "description": self.description,
            "icon": self.icon,
            "default_options": self.default_options,
            "is_popular": self.is_popular,
            "is_special": self.is_special,
            "fields": [asdict(f) for f in self.fields],
        }


BACKEND_CATALOG: list[BackendSpec] = [
    BackendSpec(
        backend_type="s3",
        label="Amazon S3 / S3-Compatible",
        category="Object Storage",
        description="Amazon S3, MinIO, Wasabi, Ceph, Cloudflare R2, Scaleway, DigitalOcean Spaces.",
        icon="cloud",
        is_popular=True,
        fields=[
            BackendField(
                name="provider",
                label="Provider S3",
                type="select",
                required=True,
                default="AWS",
                options=[
                    ("AWS", "Amazon Web Services (AWS)"),
                    ("Minio", "MinIO (Self-hosted)"),
                    ("Wasabi", "Wasabi Cloud"),
                    ("Ceph", "Ceph Object Gateway"),
                    ("Cloudflare", "Cloudflare R2"),
                    ("DigitalOcean", "DigitalOcean Spaces"),
                    ("Other", "Altro compatibile S3"),
                ],
                help_text="Tipo specifico di implementazione S3.",
            ),
            BackendField(
                name="endpoint",
                label="Endpoint URL",
                type="text",
                required=False,
                placeholder="https://s3.example.com",
                help_text="Obbligatorio per MinIO, Ceph, Wasabi o Cloudflare R2. Lasciare vuoto per AWS.",
            ),
            BackendField(
                name="region",
                label="Regione",
                type="text",
                required=False,
                default="eu-central-1",
                placeholder="eu-central-1, us-east-1, etc.",
                help_text="Regione del bucket S3.",
            ),
            BackendField(
                name="access_key_id",
                label="Access Key ID",
                type="password",
                required=True,
                is_secret=True,
                help_text="Chiave di accesso o username API.",
            ),
            BackendField(
                name="secret_access_key",
                label="Secret Access Key",
                type="password",
                required=True,
                is_secret=True,
                help_text="Chiave segreta di accesso S3.",
            ),
            BackendField(
                name="acl",
                label="Canned ACL",
                type="select",
                required=False,
                default="private",
                options=[
                    ("private", "Private"),
                    ("bucket-owner-full-control", "Bucket Owner Full Control"),
                    ("authenticated-read", "Authenticated Read"),
                ],
                help_text="Controllo accessi applicato ai nuovi oggetti caricati.",
            ),
            BackendField(
                name="storage_class",
                label="Classe di Storage",
                type="text",
                required=False,
                default="STANDARD",
                placeholder="STANDARD, GLACIER, INTELLIGENT_TIERING, etc.",
                help_text="Classe di storage di destinazione.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="b2",
        label="Backblaze B2",
        category="Object Storage",
        description="Backblaze B2 Cloud Storage economico e affidabile.",
        icon="database",
        is_popular=True,
        fields=[
            BackendField(
                name="account",
                label="Application Key ID (o Account ID)",
                type="password",
                required=True,
                is_secret=True,
                help_text="Identificativo Application Key generato dalla console Backblaze.",
            ),
            BackendField(
                name="key",
                label="Application Key",
                type="password",
                required=True,
                is_secret=True,
                help_text="Chiave segreta generata dalla console Backblaze.",
            ),
            BackendField(
                name="hard_delete",
                label="Eliminazione definitiva (Hard Delete)",
                type="boolean",
                required=False,
                default=False,
                help_text="Se abilitato, elimina definitivamente i file anziché creare versioni nascoste.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="sftp",
        label="SFTP / SSH",
        category="Server Remoto",
        description="Trasferimento sicuro su server SSH/SFTP (Linux, NAS, server remoto).",
        icon="server",
        is_popular=True,
        fields=[
            BackendField(
                name="host",
                label="Host / Indirizzo IP",
                type="text",
                required=True,
                placeholder="backup.example.com",
                help_text="Nome host o indirizzo IPv4/IPv6 del server SFTP.",
            ),
            BackendField(
                name="port",
                label="Porta SSH",
                type="number",
                required=False,
                default=22,
                help_text="Porta SSH (predefinita: 22).",
            ),
            BackendField(
                name="user",
                label="Nome Utente",
                type="text",
                required=True,
                placeholder="backupuser",
                help_text="Utente Linux o SFTP remoto.",
            ),
            BackendField(
                name="pass",
                label="Password",
                type="password",
                required=False,
                is_secret=True,
                help_text="Password di accesso (se non si utilizza chiave privata).",
            ),
            BackendField(
                name="key_pem",
                label="Chiave Privata SSH (PEM/OpenSSH)",
                type="textarea",
                required=False,
                is_secret=True,
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----\n...",
                help_text="Incolla qui la chiave privata SSH in formato OpenSSH o PEM.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="webdav",
        label="WebDAV / Nextcloud / ownCloud",
        category="Cloud / Storage",
        description="Condivisione WebDAV per Nextcloud, ownCloud, NAS Synology/QNAP.",
        icon="folder-cloud",
        is_popular=False,
        fields=[
            BackendField(
                name="url",
                label="URL WebDAV",
                type="text",
                required=True,
                placeholder="https://cloud.example.com/remote.php/dav/files/user/",
                help_text="URL completo dell'endpoint WebDAV.",
            ),
            BackendField(
                name="vendor",
                label="Piattaforma (Vendor)",
                type="select",
                required=True,
                default="nextcloud",
                options=[
                    ("nextcloud", "Nextcloud"),
                    ("owncloud", "ownCloud"),
                    ("synology", "Synology WebDAV"),
                    ("other", "Standard WebDAV"),
                ],
                help_text="Vendor del server WebDAV per ottimizzazioni di protocollo.",
            ),
            BackendField(
                name="user",
                label="Nome Utente / App Token User",
                type="text",
                required=True,
                help_text="Nome utente o username della password applicativa.",
            ),
            BackendField(
                name="pass",
                label="Password / App Password",
                type="password",
                required=True,
                is_secret=True,
                help_text="Password dell'account o App Password generata su Nextcloud.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="smb",
        label="SMB / CIFS (Windows Share)",
        category="Storage Locale & LAN",
        description="Cartelle condivise Windows o SAMBA su rete locale LAN / VPN.",
        icon="hard-drive",
        is_popular=True,
        fields=[
            BackendField(
                name="host",
                label="Host / IP Server SMB",
                type="text",
                required=True,
                placeholder="192.168.1.10",
                help_text="Indirizzo IP o nome del server Windows / SAMBA.",
            ),
            BackendField(
                name="user",
                label="Utente",
                type="text",
                required=True,
                placeholder="Administrator o domain\\user",
                help_text="Nome utente con accesso alla share.",
            ),
            BackendField(
                name="pass",
                label="Password",
                type="password",
                required=True,
                is_secret=True,
                help_text="Password di autenticazione SMB.",
            ),
            BackendField(
                name="domain",
                label="Dominio Windows (Opzionale)",
                type="text",
                required=False,
                placeholder="WORKGROUP o DOMAIN",
                help_text="Dominio Active Directory o Workgroup.",
            ),
            BackendField(
                name="port",
                label="Porta SMB",
                type="number",
                required=False,
                default=445,
                help_text="Porta SMB (predefinita: 445).",
            ),
        ],
    ),
    BackendSpec(
        backend_type="local",
        label="Disco Locale / Mount Point",
        category="Storage Locale & LAN",
        description="File system locale o punto di montaggio NFS/iSCSI visibile ai proxy.",
        icon="disc",
        is_popular=True,
        fields=[
            BackendField(
                name="copy_links",
                label="Segui collegamenti simbolici (symlinks)",
                type="boolean",
                required=False,
                default=False,
                help_text="Se abilitato, segue i symlink copiando il file puntato.",
            ),
            BackendField(
                name="links",
                label="Traduci symlinks in file .rclonelink",
                type="boolean",
                required=False,
                default=False,
                help_text="Mantiene i symlink salvandone il target come file speciale.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="drive",
        label="Google Drive",
        category="Cloud Pubblico",
        description="Google Drive personale o Workspace Shared Drive.",
        icon="google",
        is_popular=True,
        fields=[
            BackendField(
                name="client_id",
                label="Google Client ID",
                type="text",
                required=False,
                help_text="OAuth Client ID Google Cloud (opzionale per quota dedicata).",
            ),
            BackendField(
                name="client_secret",
                label="Google Client Secret",
                type="password",
                required=False,
                is_secret=True,
                help_text="OAuth Client Secret.",
            ),
            BackendField(
                name="token",
                label="OAuth Access Token JSON",
                type="textarea",
                required=True,
                is_secret=True,
                placeholder='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"..."}',
                help_text="Token OAuth generato con `rclone authorize drive` o console Google.",
            ),
            BackendField(
                name="team_drive",
                label="Shared Drive ID (Team Drive)",
                type="text",
                required=False,
                help_text="ID del drive condiviso Google Workspace (se applicabile).",
            ),
        ],
    ),
    BackendSpec(
        backend_type="azureblob",
        label="Microsoft Azure Blob Storage",
        category="Object Storage",
        description="Microsoft Azure Storage Container per blob e archiviazione cloud.",
        icon="microsoft",
        is_popular=False,
        fields=[
            BackendField(
                name="account",
                label="Storage Account Name",
                type="text",
                required=True,
                placeholder="mystorageaccount",
                help_text="Nome account storage Azure.",
            ),
            BackendField(
                name="key",
                label="Account Key",
                type="password",
                required=False,
                is_secret=True,
                help_text="Chiave di accesso primaria o secondaria (Account Key).",
            ),
            BackendField(
                name="sas_url",
                label="Shared Access Signature (SAS) URL",
                type="password",
                required=False,
                is_secret=True,
                help_text="URL SAS token alternativo all'Account Key.",
            ),
        ],
    ),
    BackendSpec(
        backend_type="onedrive",
        label="Microsoft OneDrive / SharePoint",
        category="Cloud Pubblico",
        description="OneDrive personale, OneDrive for Business e librerie documenti SharePoint.",
        icon="onedrive",
        is_popular=False,
        fields=[
            BackendField(
                name="token",
                label="OAuth Access Token JSON",
                type="textarea",
                required=True,
                is_secret=True,
                placeholder='{"access_token":"...","token_type":"Bearer","refresh_token":"...","expiry":"..."}',
                help_text="Token OAuth generato con `rclone authorize onedrive`.",
            ),
            BackendField(
                name="drive_id",
                label="Drive ID",
                type="text",
                required=False,
                help_text="Identificativo del drive OneDrive o SharePoint.",
            ),
            BackendField(
                name="drive_type",
                label="Tipo di Drive",
                type="select",
                required=False,
                default="personal",
                options=[
                    ("personal", "Personale (OneDrive)"),
                    ("business", "Aziendale / Business"),
                    ("documentLibrary", "Libreria Documenti SharePoint"),
                ],
            ),
            BackendField(
                name="client_id", label="Client ID (Opzionale)", type="text", required=False
            ),
            BackendField(
                name="client_secret",
                label="Client Secret",
                type="password",
                is_secret=True,
                required=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="dropbox",
        label="Dropbox",
        category="Cloud Pubblico",
        description="Archiviazione cloud Dropbox per utenti personali e team Dropbox Business.",
        icon="dropbox",
        is_popular=False,
        fields=[
            BackendField(
                name="token",
                label="OAuth Access Token JSON",
                type="textarea",
                required=True,
                is_secret=True,
                placeholder='{"access_token":"...","token_type":"Bearer","refresh_token":"..."}',
                help_text="Token OAuth generato con `rclone authorize dropbox`.",
            ),
            BackendField(
                name="client_id", label="App Key (Opzionale)", type="text", required=False
            ),
            BackendField(
                name="client_secret",
                label="App Secret",
                type="password",
                is_secret=True,
                required=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="box",
        label="Box.com",
        category="Cloud Pubblico",
        description="Gestione dei contenuti cloud e collaborazione protetta su Box.",
        icon="box",
        is_popular=False,
        fields=[
            BackendField(
                name="token",
                label="OAuth Access Token JSON",
                type="textarea",
                required=True,
                is_secret=True,
                placeholder='{"access_token":"...","token_type":"Bearer","refresh_token":"..."}',
                help_text="Token OAuth generato con `rclone authorize box`.",
            ),
            BackendField(name="client_id", label="Box Client ID", type="text", required=False),
            BackendField(
                name="client_secret",
                label="Box Client Secret",
                type="password",
                is_secret=True,
                required=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="pcloud",
        label="pCloud",
        category="Cloud Pubblico",
        description="Spazio di archiviazione sicuro pCloud in server europei o USA.",
        icon="pcloud",
        is_popular=False,
        fields=[
            BackendField(
                name="token",
                label="OAuth Access Token JSON",
                type="textarea",
                required=True,
                is_secret=True,
                placeholder='{"access_token":"...","token_type":"Bearer"}',
                help_text="Token OAuth generato con `rclone authorize pcloud`.",
            ),
            BackendField(
                name="hostname",
                label="Regione / Datacenter",
                type="select",
                required=True,
                default="eapi.pcloud.com",
                options=[
                    ("eapi.pcloud.com", "Europa (eapi.pcloud.com)"),
                    ("api.pcloud.com", "Stati Uniti (api.pcloud.com)"),
                ],
            ),
        ],
    ),
    BackendSpec(
        backend_type="ftp",
        label="FTP / FTPS",
        category="Server Remoto",
        description="Protocollo FTP standard con supporto a crittografia esplicita FTPS (TLS).",
        icon="ftp",
        is_popular=False,
        fields=[
            BackendField(
                name="host",
                label="Host / Server FTP",
                type="text",
                required=True,
                placeholder="ftp.example.com",
            ),
            BackendField(name="port", label="Porta FTP", type="number", required=False, default=21),
            BackendField(
                name="user",
                label="Utente FTP",
                type="text",
                required=True,
                placeholder="anonymous o ftpuser",
            ),
            BackendField(
                name="pass", label="Password", type="password", is_secret=True, required=True
            ),
            BackendField(
                name="tls",
                label="Abilita FTPS (TLS)",
                type="boolean",
                required=False,
                default=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="google cloud storage",
        label="Google Cloud Storage (GCS)",
        category="Object Storage",
        description="Google Cloud Platform Cloud Storage con supporto Service Account.",
        icon="google",
        is_popular=False,
        fields=[
            BackendField(
                name="project_number",
                label="Project ID / Number",
                type="text",
                required=False,
                placeholder="my-gcp-project",
            ),
            BackendField(
                name="service_account_credentials",
                label="Service Account JSON",
                type="textarea",
                required=False,
                is_secret=True,
                placeholder='{"type": "service_account", "project_id": "...", ...}',
                help_text="Contenuto della chiave JSON scaricata dalla console GCP.",
            ),
            BackendField(
                name="anonymous",
                label="Accesso Pubblico / Anonimo",
                type="boolean",
                required=False,
                default=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="swift",
        label="OpenStack Swift / OVH",
        category="Object Storage",
        description="Object storage distribuito basato su API OpenStack Swift o cloud provider OVH.",
        icon="swift",
        is_popular=False,
        fields=[
            BackendField(name="user", label="Nome Utente", type="text", required=True),
            BackendField(
                name="key",
                label="API Key o Password",
                type="password",
                is_secret=True,
                required=True,
            ),
            BackendField(
                name="auth",
                label="Auth URL",
                type="text",
                required=True,
                placeholder="https://auth.cloud.ovh.net/v3",
            ),
            BackendField(name="tenant", label="Tenant / Project Name", type="text", required=False),
            BackendField(name="domain", label="Domain Name", type="text", required=False),
        ],
    ),
    BackendSpec(
        backend_type="mega",
        label="Mega.nz",
        category="Cloud Pubblico",
        description="Archiviazione cloud cifrata end-to-end su Mega.",
        icon="mega",
        is_popular=False,
        fields=[
            BackendField(
                name="user",
                label="Email Account",
                type="text",
                required=True,
                placeholder="utente@example.com",
            ),
            BackendField(
                name="pass", label="Password", type="password", is_secret=True, required=True
            ),
        ],
    ),
    BackendSpec(
        backend_type="opendrive",
        label="OpenDrive",
        category="Cloud Pubblico",
        description="Servizio di backup e archiviazione cloud OpenDrive.",
        icon="cloud",
        is_popular=False,
        fields=[
            BackendField(name="username", label="Email / Username", type="text", required=True),
            BackendField(
                name="password", label="Password", type="password", is_secret=True, required=True
            ),
        ],
    ),
    BackendSpec(
        backend_type="protondrive",
        label="Proton Drive",
        category="Cloud Pubblico",
        description="Storage sicuro e cifrato con crittografia ad accesso zero Proton.",
        icon="protondrive",
        is_popular=False,
        fields=[
            BackendField(name="username", label="Username Proton", type="text", required=True),
            BackendField(
                name="password", label="Password", type="password", is_secret=True, required=True
            ),
            BackendField(
                name="2fa",
                label="Codice 2FA (se abilitato)",
                type="password",
                is_secret=True,
                required=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="koofr",
        label="Koofr / Digi Storage",
        category="Cloud Pubblico",
        description="Cloud storage europeo conforme GDPR (Koofr, Digi Storage, ecc.).",
        icon="folder-cloud",
        is_popular=False,
        fields=[
            BackendField(name="user", label="Email Account", type="text", required=True),
            BackendField(
                name="password",
                label="Password Applicativa",
                type="password",
                is_secret=True,
                required=True,
            ),
            BackendField(
                name="endpoint",
                label="Endpoint URL",
                type="text",
                required=False,
                default="https://app.koofr.net",
            ),
        ],
    ),
    BackendSpec(
        backend_type="qingstor",
        label="QingStor Object Storage",
        category="Object Storage",
        description="QingCloud QingStor storage per oggetti su scala enterprise.",
        icon="database",
        is_popular=False,
        fields=[
            BackendField(
                name="env",
                label="Regione / Datacenter",
                type="text",
                required=False,
                default="pek3a",
            ),
            BackendField(
                name="access_key_id",
                label="Access Key ID",
                type="password",
                is_secret=True,
                required=True,
            ),
            BackendField(
                name="secret_access_key",
                label="Secret Access Key",
                type="password",
                is_secret=True,
                required=True,
            ),
        ],
    ),
    BackendSpec(
        backend_type="yandex",
        label="Yandex Disk",
        category="Cloud Pubblico",
        description="Archiviazione cloud Yandex Disk con autenticazione OAuth.",
        icon="cloud",
        is_popular=False,
        fields=[
            BackendField(
                name="token", label="OAuth Token", type="textarea", is_secret=True, required=True
            ),
            BackendField(
                name="client_id", label="Client ID (Opzionale)", type="text", required=False
            ),
            BackendField(
                name="client_secret",
                label="Client Secret",
                type="password",
                is_secret=True,
                required=False,
            ),
        ],
    ),
    BackendSpec(
        backend_type="zoho",
        label="Zoho WorkDrive",
        category="Cloud Pubblico",
        description="Collaborazione e storage documentale su Zoho WorkDrive.",
        icon="cloud",
        is_popular=False,
        fields=[
            BackendField(
                name="token", label="OAuth Token", type="textarea", is_secret=True, required=True
            ),
            BackendField(
                name="region",
                label="Regione Datacenter Zoho",
                type="select",
                required=True,
                default="eu",
                options=[
                    ("eu", "Europa (.eu)"),
                    ("com", "Stati Uniti (.com)"),
                    ("in", "India (.in)"),
                    ("com.au", "Australia (.com.au)"),
                ],
            ),
        ],
    ),
    BackendSpec(
        backend_type="http",
        label="HTTP Server (Read-Only)",
        category="Server Remoto",
        description="Server HTTP o HTTPS remoto per download e replica in sola lettura.",
        icon="http",
        is_popular=False,
        fields=[
            BackendField(
                name="url",
                label="URL Base",
                type="text",
                required=True,
                placeholder="https://pub.example.com/data/",
            ),
        ],
    ),
    BackendSpec(
        backend_type="alias",
        label="Alias",
        category="Backend Speciale",
        description="Puntatore alias che reindirizza verso il percorso di un altro remote configurato.",
        icon="link",
        is_popular=False,
        is_special=True,
        fields=[
            BackendField(
                name="remote",
                label="Target Remote (es. remote:path)",
                type="text",
                required=True,
                placeholder="mioremote:cartella",
                help_text="Remote e percorso di destinazione a cui puntare",
            ),
        ],
    ),
    BackendSpec(
        backend_type="crypt",
        label="Crypt (Crittografia)",
        category="Backend Speciale",
        description="Cifra file e cartelle trasparentemente appoggiandosi ad un remote sottostante.",
        icon="lock",
        is_popular=False,
        is_special=True,
        fields=[
            BackendField(
                name="remote",
                label="Remote Sottostante (es. remote:path)",
                type="text",
                required=True,
                placeholder="miodrive:cartella_cifrata",
                help_text="Remote e percorso sottostante su cui salvare i dati cifrati",
            ),
            BackendField(
                name="password",
                label="Password Principale",
                type="password",
                required=True,
                is_secret=True,
                help_text="Password usata per cifrare i dati",
            ),
            BackendField(
                name="password2",
                label="Password Secondaria / Salt",
                type="password",
                required=False,
                is_secret=True,
                help_text="Password secondaria opzionale usata come salt di sicurezza",
            ),
            BackendField(
                name="filename_encryption",
                label="Cifratura Nomi File",
                type="select",
                options=[
                    ("standard", "Standard (base32768/base32)"),
                    ("obfuscate", "Offuscamento semplice"),
                    ("off", "Disattivata (nomi in chiaro)"),
                ],
                default="standard",
                help_text="Modalità di offuscamento dei nomi dei file",
            ),
            BackendField(
                name="directory_name_encryption",
                label="Cifra Nomi Directory",
                type="boolean",
                default=True,
                help_text="Se abilitato, anche i nomi delle cartelle vengono cifrati",
            ),
        ],
    ),
    BackendSpec(
        backend_type="compress",
        label="Compress (Compressione)",
        category="Backend Speciale",
        description="Comprime e decomprime i file al volo memorizzandoli compressi su un remote sottostante.",
        icon="archive",
        is_popular=False,
        is_special=True,
        fields=[
            BackendField(
                name="remote",
                label="Remote Sottostante (es. remote:path)",
                type="text",
                required=True,
                placeholder="mioremote:cartella_compressa",
                help_text="Remote e percorso sottostante su cui salvare i file compressi",
            ),
            BackendField(
                name="compression_mode",
                label="Metodo di Compressione",
                type="select",
                options=[("gzip", "gzip (standard RClone)")],
                default="gzip",
                help_text="Algoritmo di compressione",
            ),
        ],
    ),
    BackendSpec(
        backend_type="chunker",
        label="Chunker (Suddivisione)",
        category="Backend Speciale",
        description="Suddivide file di grandi dimensioni in blocchi trasparenti per superare limiti di upload del provider.",
        icon="layers",
        is_popular=False,
        is_special=True,
        fields=[
            BackendField(
                name="remote",
                label="Remote Sottostante (es. remote:path)",
                type="text",
                required=True,
                placeholder="mioremote:cartella_chunked",
                help_text="Remote e percorso sottostante per memorizzare i chunk",
            ),
            BackendField(
                name="chunk_size",
                label="Dimensione Frammenti (Chunk Size)",
                type="text",
                required=False,
                default="500M",
                placeholder="es. 500M, 1G, 2G",
                help_text="Dimensione massima di ciascun frammento",
            ),
            BackendField(
                name="name_format",
                label="Pattern Nome Chunk",
                type="text",
                required=False,
                default="*.rclone_chunk.###",
                placeholder="*.rclone_chunk.###",
                help_text="Pattern per i file frammentati",
            ),
            BackendField(
                name="hash_type",
                label="Algoritmo di Hash",
                type="select",
                options=[("md5", "MD5"), ("sha1", "SHA-1"), ("none", "Nessuno")],
                default="md5",
                help_text="Algoritmo di checksum tra i blocchi",
            ),
        ],
    ),
    BackendSpec(
        backend_type="union",
        label="Union (Aggregazione)",
        category="Backend Speciale",
        description="Unisce e aggrega molteplici remote sottostanti in un unico spazio logico con policy personalizzate.",
        icon="git-merge",
        is_popular=False,
        is_special=True,
        fields=[
            BackendField(
                name="upstreams",
                label="Remote Upstream (spazio-separati)",
                type="text",
                required=True,
                placeholder="remote1:path remote2:path",
                help_text="Elenco di remote/percorsi separati da spazio (es. s3-a:backup b2-b:backup)",
            ),
            BackendField(
                name="action_policy",
                label="Action Policy",
                type="select",
                options=[
                    ("epall", "epall (tutti i remote con percorso)"),
                    ("all", "all (tutti i remote)"),
                    ("lfs", "lfs (più spazio libero)"),
                    ("ff", "ff (primo trovato)"),
                ],
                default="epall",
            ),
            BackendField(
                name="create_policy",
                label="Create Policy",
                type="select",
                options=[
                    ("epmfs", "epmfs (percorso esistente con più spazio)"),
                    ("mfs", "mfs (più spazio libero)"),
                    ("lfs", "lfs (meno spazio libero)"),
                    ("rand", "rand (casuale)"),
                    ("ff", "ff (primo upstream)"),
                ],
                default="epmfs",
            ),
            BackendField(
                name="search_policy",
                label="Search Policy",
                type="select",
                options=[("ff", "ff (primo upstream trovato)"), ("all", "all (cerca in tutti)")],
                default="ff",
            ),
        ],
    ),
]

_CATALOG_BY_TYPE: dict[str, BackendSpec] = {spec.backend_type: spec for spec in BACKEND_CATALOG}


def get_backend_catalog() -> list[BackendSpec]:
    """Retrieve full catalog of supported RClone backend specifications."""
    return list(BACKEND_CATALOG)


def get_backend_spec(backend_type: str) -> BackendSpec | None:
    """Retrieve specification for a given backend type code."""
    return _CATALOG_BY_TYPE.get(backend_type)


def is_obscured_secret_field(backend_type: str, field_name: str) -> bool:
    """Determine whether an RClone backend parameter expects obscured password input.

    RClone expects passwords for backends like smb, sftp, webdav, ftp, mega, opendrive,
    protondrive, koofr, crypt (password, password2) to be obscured via AES-CTR.
    API keys / access keys (e.g. S3, B2, Azure, OAuth secrets) must remain plaintext.
    """
    fn = str(field_name).lower()
    bt = str(backend_type).lower()

    # Generic pass / password fields
    if fn in ("pass", "password", "password2"):
        return True
    if fn.endswith("_pass") or fn.endswith("_password"):
        return True

    # Provider specific
    if bt == "crypt" and fn in ("password", "password2"):
        return True
    if bt in (
        "smb",
        "sftp",
        "webdav",
        "ftp",
        "mega",
        "opendrive",
        "protondrive",
        "koofr",
    ) and fn in ("pass", "password"):
        return True

    return False


class RemoteConfigValidationError(ValueError):
    """Raised when remote configuration is invalid, carrying field metadata for localization."""

    def __init__(
        self,
        message: str,
        field_name: str | None = None,
        field_label: str | None = None,
        error_type: str = "validation",
    ) -> None:
        super().__init__(message)
        self.field_name = field_name
        self.field_label = field_label
        self.error_type = error_type


def validate_and_split_remote_config(
    backend_type: str,
    raw_config: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Validate remote configuration against backend specification.

    Returns:
        tuple of (public_params, secret_params, secret_field_names)
    Raises:
        RemoteConfigValidationError (subclass of ValueError) if backend_type is unknown or required fields are missing.
    """
    spec = get_backend_spec(backend_type)
    if spec is None:
        raise RemoteConfigValidationError(
            f"Tipo di backend '{backend_type}' non supportato.",
            error_type="unsupported_backend",
        )

    public_params: dict[str, Any] = {}
    secret_params: dict[str, Any] = {}
    secret_field_names: list[str] = []

    for f in spec.fields:
        val = raw_config.get(f.name)
        if val is None or val == "":
            val = f.default

        if f.required and (val is None or val == ""):
            raise RemoteConfigValidationError(
                f"Il campo obbligatorio '{f.label}' non è stato specificato.",
                field_name=f.name,
                field_label=f.label,
                error_type="required",
            )

        if val is not None:
            # Type cast
            if f.type == "number" and isinstance(val, (str, int, float)):
                try:
                    val = int(val)
                except ValueError:
                    raise RemoteConfigValidationError(
                        f"Il campo '{f.label}' deve essere un numero intero valido.",
                        field_name=f.name,
                        field_label=f.label,
                        error_type="invalid_number",
                    ) from None
            elif f.type == "boolean":
                val = str(val).lower() in ("true", "1", "yes", "on")

            if f.is_secret:
                secret_params[f.name] = val
                secret_field_names.append(f.name)
            else:
                public_params[f.name] = val

    # Include any additional arbitrary options under extra options if provided
    for k, v in raw_config.items():
        if (
            k not in public_params
            and k not in secret_params
            and k not in [f.name for f in spec.fields]
        ):
            public_params[k] = v

    return public_params, secret_params, secret_field_names
