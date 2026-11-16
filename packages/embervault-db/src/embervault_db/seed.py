"""Idempotent seed data for system roles and permissions."""

from __future__ import annotations

import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from embervault_common.security.passwords import hash_password
from embervault_db.models.auth import Permission, Role, User

DEFAULT_PERMISSIONS: dict[str, dict[str, str]] = {
    # Categoria: Job
    "job.read": {
        "name": "Visualizzazione",
        "category": "Job",
        "description": "Visualizzazione configurazione, stato ed elenco delle esecuzioni dei job",
    },
    "job.create": {
        "name": "Creazione",
        "category": "Job",
        "description": "Creazione e configurazione di nuovi job di sincronizzazione o copia",
    },
    "job.update": {
        "name": "Modifica",
        "category": "Job",
        "description": "Modifica impostazioni, pianificazioni e parametri dei job esistenti",
    },
    "job.delete": {
        "name": "Eliminazione",
        "category": "Job",
        "description": "Eliminazione definitiva dei job di backup",
    },
    "job.run": {
        "name": "Esecuzione",
        "category": "Job",
        "description": "Avvio manuale, arresto e annullamento delle esecuzioni dei job",
    },
    "job.write": {
        "name": "Gestione Completa",
        "category": "Job",
        "description": "Creazione, modifica ed eliminazione job (permesso cumulativo)",
    },
    # Categoria: Remote Storage
    "remote.read": {
        "name": "Visualizzazione",
        "category": "Remote Storage",
        "description": "Visualizzazione configurazione e stato degli storage remoti",
    },
    "remote.create": {
        "name": "Creazione",
        "category": "Remote Storage",
        "description": "Configurazione e test di connessione per nuovi storage remoti",
    },
    "remote.update": {
        "name": "Modifica",
        "category": "Remote Storage",
        "description": "Modifica credenziali e opzioni degli storage remoti",
    },
    "remote.delete": {
        "name": "Eliminazione",
        "category": "Remote Storage",
        "description": "Eliminazione definitiva degli storage remoti",
    },
    "remote.browse": {
        "name": "Esplorazione File Remoti",
        "category": "Remote Storage",
        "description": "Navigazione e consultazione dell'albero delle directory e dei file remoti",
    },
    "remote.download": {
        "name": "Download File & Archivi",
        "category": "Remote Storage",
        "description": "Download di singoli file o generazione archivi ZIP da storage remoti",
    },
    "remote.test": {
        "name": "Test Connessione",
        "category": "Remote Storage",
        "description": "Verifica della connettività e credenziali verso lo storage remoto",
    },
    "remote.write": {
        "name": "Gestione Completa",
        "category": "Remote Storage",
        "description": "Creazione, modifica, eliminazione e test remote (permesso cumulativo)",
    },
    # Categoria: Nodi Proxy
    "proxy.read": {
        "name": "Visualizzazione",
        "category": "Nodi Proxy",
        "description": "Visualizzazione nodi proxy, stato di salute e metriche di esecuzione",
    },
    "proxy.create": {
        "name": "Registrazione",
        "category": "Nodi Proxy",
        "description": "Registrazione e verifica impronta digitale di nuovi nodi proxy",
    },
    "proxy.update": {
        "name": "Modifica",
        "category": "Nodi Proxy",
        "description": "Abilitazione, disabilitazione e modifica parametri di esecuzione dei proxy",
    },
    "proxy.delete": {
        "name": "Eliminazione",
        "category": "Nodi Proxy",
        "description": "Revoca e rimozione di nodi proxy dalla flotta",
    },
    "proxy.upgrade": {
        "name": "Aggiornamento Rclone",
        "category": "Nodi Proxy",
        "description": "Aggiornamento o downgrade della versione di Rclone installata sui proxy",
    },
    "proxy.retrust": {
        "name": "Retrust Certificato TLS",
        "category": "Nodi Proxy",
        "description": "Riconoscimento e approvazione nuova impronta digitale del certificato TLS",
    },
    "proxy.renew_cert": {
        "name": "Rinnovo Certificato TLS",
        "category": "Nodi Proxy",
        "description": "Richiesta di rinnovo anticipato del certificato TLS sui proxy",
    },
    "proxy.manage": {
        "name": "Gestione Completa",
        "category": "Nodi Proxy",
        "description": "Registrazione, abilitazione, aggiornamento e gestione proxy (permesso cumulativo)",
    },
    # Categoria: Portale Pubblico
    "share.read": {
        "name": "Visualizzazione",
        "category": "Portale Pubblico",
        "description": "Visualizzazione e consultazione dei link pubblici di condivisione",
    },
    "share.create": {
        "name": "Creazione di link pubblici",
        "category": "Portale Pubblico",
        "description": "Creazione di nuovi link pubblici di condivisione e download con scadenza",
    },
    "share.update": {
        "name": "Modifica di link pubblici",
        "category": "Portale Pubblico",
        "description": "Modifica della data di scadenza e impostazioni dei link pubblici",
    },
    "share.deactivate": {
        "name": "Disattivazione di link pubblici",
        "category": "Portale Pubblico",
        "description": "Disattivazione immediata di link pubblici attivi",
    },
    "share.delete": {
        "name": "Eliminazione di link pubblici",
        "category": "Portale Pubblico",
        "description": "Eliminazione definitiva di link pubblici di condivisione",
    },
    "share.write": {
        "name": "Gestione Completa",
        "category": "Portale Pubblico",
        "description": "Creazione, modifica, disattivazione ed eliminazione link pubblici (permesso cumulativo)",
    },
    # Categoria: Notifiche
    "notification.read": {
        "name": "Visualizzazione Canali",
        "category": "Notifiche",
        "description": "Visualizzazione dei canali e delle impostazioni di notifica",
    },
    "notification.write": {
        "name": "Gestione Canali & Test",
        "category": "Notifiche",
        "description": "Configurazione, modifica, eliminazione e test invio allarmi su canali di notifica",
    },
    # Categoria: Identità & Directory
    "identity.read": {
        "name": "Visualizzazione Integrazioni",
        "category": "Identità & Directory",
        "description": "Visualizzazione parametri di configurazione LDAP e Single Sign-On OIDC",
    },
    "identity.write": {
        "name": "Gestione Integrazioni",
        "category": "Identità & Directory",
        "description": "Configurazione credenziali, bind LDAP, mapping ruoli e provider OIDC/SSO",
    },
    # Categoria: Intelligenza Artificiale
    "ai.read": {
        "name": "Visualizzazione Impostazioni IA",
        "category": "Intelligenza Artificiale",
        "description": "Visualizzazione configurazione e provider di intelligenza artificiale",
    },
    "ai.write": {
        "name": "Gestione Provider IA",
        "category": "Intelligenza Artificiale",
        "description": "Configurazione chiavi API, modelli e parametri del motore di intelligenza artificiale",
    },
    "ai.diagnostics": {
        "name": "Diagnostica Errori IA",
        "category": "Intelligenza Artificiale",
        "description": "Consultazione del registro errori e delle decisioni diagnostiche generate dall'IA",
    },
    # Categoria: Personalizzazione & Branding
    "appearance.read": {
        "name": "Visualizzazione Branding",
        "category": "Personalizzazione & Branding",
        "description": "Visualizzazione impostazioni grafiche, loghi e personalizzazioni",
    },
    "appearance.write": {
        "name": "Modifica Aspetto & Whitelabel",
        "category": "Personalizzazione & Branding",
        "description": "Caricamento loghi, sfondi di login e personalizzazione del nome dell'applicazione",
    },
    # Categoria: Utenti & Ruoli
    "user.read": {
        "name": "Visualizzazione Utenti",
        "category": "Utenti & Ruoli",
        "description": "Visualizzazione account utente, sessioni attive e ruoli assegnati",
    },
    "user.create": {
        "name": "Creazione Utenti",
        "category": "Utenti & Ruoli",
        "description": "Creazione di nuovi account utente locali",
    },
    "user.update": {
        "name": "Modifica Utenti",
        "category": "Utenti & Ruoli",
        "description": "Modifica profilo, reimpostazione credenziali e assegnazione ruoli",
    },
    "user.delete": {
        "name": "Eliminazione Utenti",
        "category": "Utenti & Ruoli",
        "description": "Disattivazione ed eliminazione definitiva degli account utente",
    },
    "user.manage": {
        "name": "Gestione Utenti Completa",
        "category": "Utenti & Ruoli",
        "description": "Creazione, modifica ed eliminazione utenti (permesso cumulativo)",
    },
    "role.read": {
        "name": "Visualizzazione Ruoli",
        "category": "Utenti & Ruoli",
        "description": "Visualizzazione elenco ruoli e matrice permessi RBAC",
    },
    "role.manage": {
        "name": "Gestione Ruoli & Matrice",
        "category": "Utenti & Ruoli",
        "description": "Creazione ed eliminazione ruoli personalizzati e modifica matrice permessi",
    },
    # Categoria: Autenticazione (Enforcement 2FA)
    "auth.enforce_2fa": {
        "name": "2FA Obbligatoria",
        "category": "Autenticazione",
        "description": "Richiede obbligatoriamente l'autenticazione a due fattori (TOTP) al login",
    },
    # Categoria: Backup & Restore Sistema
    "backup.read": {
        "name": "Visualizzazione Backup",
        "category": "Backup & Restore Sistema",
        "description": "Visualizzazione storico e configurazione dei backup di sistema",
    },
    "backup.export": {
        "name": "Esportazione Backup",
        "category": "Backup & Restore Sistema",
        "description": "Esecuzione manuale ed esportazione/download di backup del sistema",
    },
    "backup.restore": {
        "name": "Ripristino Database",
        "category": "Backup & Restore Sistema",
        "description": "Importazione e ripristino del database dell'applicazione da backup",
    },
    "backup.manage": {
        "name": "Gestione Completa Backup",
        "category": "Backup & Restore Sistema",
        "description": "Configurazione, esportazione e ripristino backup (permesso cumulativo)",
    },
    # Categoria: Impostazioni & Sistema
    "settings.read": {
        "name": "Visualizzazione Impostazioni",
        "category": "Impostazioni & Sistema",
        "description": "Visualizzazione parametri di sistema, Rclone e configurazioni generali",
    },
    "settings.write": {
        "name": "Modifica Impostazioni",
        "category": "Impostazioni & Sistema",
        "description": "Modifica parametri generali di sistema e opzioni globali di Rclone",
    },
    "network.manage": {
        "name": "Gestione Rete & Proxies",
        "category": "Impostazioni & Sistema",
        "description": "Configurazione subnet e reverse proxy fidati per l'anti-spoofing IP",
    },
    "hooks.manage": {
        "name": "Gestione Lifecycle Hooks",
        "category": "Impostazioni & Sistema",
        "description": "Configurazione di script e webhook invocati agli eventi di sistema",
    },
    "crypto.rotate": {
        "name": "Rotazione Crittografica",
        "category": "Impostazioni & Sistema",
        "description": "Esecuzione della rotazione delle chiavi crittografiche envelope",
    },
    # Categoria: Audit & Monitoraggio
    "audit.read": {
        "name": "Consultazione Audit Log",
        "category": "Audit & Monitoraggio",
        "description": "Consultazione del registro eventi di audit trail immutabile",
    },
    "audit.export": {
        "name": "Esportazione Audit Log",
        "category": "Audit & Monitoraggio",
        "description": "Esportazione massiva in file dei log di audit trail",
    },
    "metrics.read": {
        "name": "Visualizzazione Metriche & Realtime",
        "category": "Audit & Monitoraggio",
        "description": "Accesso a metriche di throughput, monitoraggio e flussi di eventi SSE",
    },
}

DEFAULT_ROLES: dict[str, dict[str, str]] = {
    "Administrator": {
        "description": "Amministratore completo con pieno accesso a tutte le funzionalità",
    },
    "Operator": {
        "description": "Operatore con permessi di esecuzione job e gestione operativa",
    },
    "Viewer": {
        "description": "Accesso in sola lettura a job, remote, proxy e log",
    },
}

# Permessi associati per ruolo di default
ALL_PERMISSION_CODES = list(DEFAULT_PERMISSIONS.keys())
ROLE_PERMISSION_MAPPING: dict[str, list[str]] = {
    "Administrator": [code for code in ALL_PERMISSION_CODES if code != "auth.enforce_2fa"],
    "Operator": [
        "remote.read",
        "remote.create",
        "remote.update",
        "remote.write",
        "remote.browse",
        "remote.download",
        "remote.test",
        "job.read",
        "job.create",
        "job.update",
        "job.run",
        "job.write",
        "proxy.read",
        "proxy.manage",
        "proxy.upgrade",
        "proxy.renew_cert",
        "audit.read",
        "metrics.read",
        "user.read",
        "role.read",
        "share.read",
        "share.create",
        "share.update",
        "share.deactivate",
        "share.delete",
        "share.write",
        "ai.diagnostics",
    ],
    "Viewer": [
        "remote.read",
        "remote.browse",
        "job.read",
        "proxy.read",
        "audit.read",
        "metrics.read",
        "share.read",
        "ai.diagnostics",
    ],
}


def seed_initial_data(session: Session) -> None:
    """Idempotently seed default permissions, roles, and role-permission mappings."""
    # 1. Seed or Update Permissions with category and friendly name
    existing_perms = {p.code: p for p in session.scalars(select(Permission)).all()}
    for code, meta in DEFAULT_PERMISSIONS.items():
        if code not in existing_perms:
            perm = Permission(
                code=code,
                name=meta["name"],
                category=meta["category"],
                description=meta["description"],
            )
            session.add(perm)
            existing_perms[code] = perm
        else:
            perm = existing_perms[code]
            perm.name = meta["name"]
            perm.category = meta["category"]
            perm.description = meta["description"]

    session.flush()

    # 2. Seed Roles (handle renaming legacy admin/operator/viewer to Administrator/Operator/Viewer)
    existing_roles = {r.name: r for r in session.scalars(select(Role)).all()}

    # Migration rename if lowercase names exist
    legacy_map = {"admin": "Administrator", "operator": "Operator", "viewer": "Viewer"}
    for old_name, new_name in legacy_map.items():
        if old_name in existing_roles and new_name not in existing_roles:
            r = existing_roles.pop(old_name)
            r.name = new_name
            r.is_system = True
            existing_roles[new_name] = r

    for name, meta in DEFAULT_ROLES.items():
        if name not in existing_roles:
            role = Role(name=name, description=meta["description"], is_system=True)
            session.add(role)
            existing_roles[name] = role
        else:
            existing_roles[name].is_system = True
            existing_roles[name].description = meta["description"]

    session.flush()

    # 3. Associate Permissions to Roles
    for role_name, perm_codes in ROLE_PERMISSION_MAPPING.items():
        role = existing_roles.get(role_name)
        if role:
            desired_perms = [existing_perms[code] for code in perm_codes if code in existing_perms]
            role.permissions = desired_perms

    session.flush()

    # 4. Bootstrap Default Admin User (if not already existing)
    admin_user = session.scalar(select(User).where(User.username == "admin"))
    admin_role = existing_roles.get("Administrator") or existing_roles.get("admin")
    if admin_user is None and admin_role is not None:
        initial_password = os.environ.get("EMBERVAULT_INITIAL_ADMIN_PASSWORD")
        must_change = False
        if not initial_password:
            initial_password = "admin"
            must_change = True

        hashed = hash_password(initial_password)
        admin = User(
            username="admin",
            email="admin@embervault.local",
            display_name="Administrator",
            password_hash=hashed,
            auth_source="local",
            role_id=admin_role.id,
            is_active=True,
            must_change_password=must_change,
        )
        session.add(admin)
        session.flush()
    elif admin_user is not None and admin_role is not None:
        if admin_user.role_id != admin_role.id:
            admin_user.role_id = admin_role.id

    from embervault_common.config import is_demo_mode
    if is_demo_mode():
        seed_demo_data(session)
    else:
        session.commit()


def seed_demo_data(session: Session) -> None:
    """Idempotently seed demo user, remotes, proxies, and backup job for Demo Mode."""
    from uuid import uuid4
    from embervault_common.security.crypto import (
        KeyRing,
        get_default_key_ring,
        set_default_key_ring,
    )
    from embervault_db.models.base import utc_now
    from embervault_db.models.proxy import Proxy, ProxyStatus
    from embervault_db.models.remotes import Job, RcloneRemote
    from embervault_db.repositories.job_repository import JobRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository
    from embervault_db.repositories.remote_repository import RemoteRepository

    # Ensure key ring has a primary key available for encrypting credentials
    try:
        ring = get_default_key_ring()
        ring.get_primary_key()
    except Exception:
        ring = get_default_key_ring()
        ring.add_key("v1", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", is_primary=True)

    # 1. Demo Administrator User (username="demo", password="demo")
    demo_user = session.scalar(select(User).where(User.username == "demo"))
    admin_role = session.scalar(select(Role).where(Role.name == "Administrator")) or session.scalar(
        select(Role).where(Role.name == "admin")
    )
    if demo_user is None and admin_role is not None:
        demo_user = User(
            username="demo",
            email="demo@embervault.local",
            display_name="Demo Administrator",
            password_hash=hash_password("demo"),
            auth_source="local",
            role_id=admin_role.id,
            is_active=True,
            must_change_password=False,
        )
        session.add(demo_user)
        session.flush()

    # 2. Two Demo Remotes
    src_remote = session.scalar(
        select(RcloneRemote).where(RcloneRemote.name == "Demo Local Source")
    )
    if src_remote is None:
        src_remote = RemoteRepository.create_remote(
            session=session,
            name="Demo Local Source",
            backend_type="local",
            raw_config={"path": "/demo/data/source"},
            created_by=demo_user.id if demo_user else None,
        )

    dst_remote = session.scalar(
        select(RcloneRemote).where(RcloneRemote.name == "Demo Cloud Destination")
    )
    if dst_remote is None:
        dst_remote = RemoteRepository.create_remote(
            session=session,
            name="Demo Cloud Destination",
            backend_type="local",
            raw_config={"path": "/demo/data/destination"},
            created_by=demo_user.id if demo_user else None,
        )

    # 3. Two Demo Proxies
    p1 = session.scalar(select(Proxy).where(Proxy.name == "Demo Edge Proxy 01"))
    if p1 is None:
        p1_id = uuid4()
        p1 = Proxy(
            id=p1_id,
            name="Demo Edge Proxy 01",
            host="127.0.0.1",
            port=8443,
            is_enabled=True,
            cert_fingerprint_sha256="demo_sha256_fp_proxy_01",
            token_encrypted=ProxyRepository.encrypt_token(
                "demo-proxy-token-32-chars-minimum-01", p1_id
            ),
            max_concurrent_tasks=2,
            proxy_version="1.0.0",
            rclone_version="v1.66.0",
        )
        session.add(p1)
        session.flush()
        ps1 = ProxyStatus(
            proxy_id=p1.id,
            state="online",
            last_seen_at=utc_now(),
            last_check_at=utc_now(),
        )
        session.add(ps1)

    p2 = session.scalar(select(Proxy).where(Proxy.name == "Demo Edge Proxy 02"))
    if p2 is None:
        p2_id = uuid4()
        p2 = Proxy(
            id=p2_id,
            name="Demo Edge Proxy 02",
            host="127.0.0.1",
            port=8444,
            is_enabled=True,
            cert_fingerprint_sha256="demo_sha256_fp_proxy_02",
            token_encrypted=ProxyRepository.encrypt_token(
                "demo-proxy-token-32-chars-minimum-02", p2_id
            ),
            max_concurrent_tasks=2,
            proxy_version="1.0.0",
            rclone_version="v1.66.0",
        )
        session.add(p2)
        session.flush()
        ps2 = ProxyStatus(
            proxy_id=p2.id,
            state="online",
            last_seen_at=utc_now(),
            last_check_at=utc_now(),
        )
        session.add(ps2)

    # Ensure proxy reachability to both demo remotes
    all_demo_remotes = [r for r in (src_remote, dst_remote) if r is not None]
    if p1 is not None and all_demo_remotes:
        p1.reachable_remotes = list(set(list(p1.reachable_remotes) + all_demo_remotes))
    if p2 is not None and all_demo_remotes:
        p2.reachable_remotes = list(set(list(p2.reachable_remotes) + all_demo_remotes))
    session.flush()

    # 4. Demo Backup Job (syncs root of source remote to root of destination remote)
    demo_job = session.scalar(select(Job).where(Job.name == "Demo Backup & Sync"))
    if demo_job is None and src_remote is not None and dst_remote is not None:
        assigned_proxies = [p.id for p in (p1, p2) if p is not None]
        JobRepository.create_job(
            session=session,
            name="Demo Backup & Sync",
            source_remote_id=src_remote.id,
            source_path="/",
            destination_remote_id=dst_remote.id,
            destination_path="/",
            operation="sync",
            parallelization="none",
            assigned_proxy_ids=assigned_proxies,
            is_enabled=True,
            created_by=demo_user.id if demo_user else None,
        )

    session.commit()
