/**
 * Proxy Registration & Probe TOFU Workflow
 */

document.addEventListener('DOMContentLoaded', () => {
  const openModalBtn = document.getElementById('btn-open-register-modal');
  const probeBtn = document.getElementById('btn-probe-proxy');
  const confirmBtn = document.getElementById('btn-confirm-register');

  if (openModalBtn) {
    openModalBtn.addEventListener('click', () => {
      openModal('modal-register-proxy');
    });
  }

  if (probeBtn) {
    probeBtn.addEventListener('click', handleProbe);
  }

  if (confirmBtn) {
    confirmBtn.addEventListener('click', handleRegister);
  }

  // Edit Proxy Handlers
  const proxyEnabledInput = document.getElementById('edit-proxy-enabled');
  const btnToggleProxyEnabled = document.getElementById('btn-toggle-proxy-enabled');
  const activeTasksWarning = document.getElementById('edit-proxy-active-tasks-warning');

  function updateProxyEnabledButtonState() {
    if (!btnToggleProxyEnabled || !proxyEnabledInput) return;
    const isEnabled = proxyEnabledInput.value === 'true';
    const activeLabel = btnToggleProxyEnabled.getAttribute('data-label-active') || window._t('active', 'Attivo');
    const disabledLabel = btnToggleProxyEnabled.getAttribute('data-label-disabled') || window._t('disabled', 'Disattivato');
    btnToggleProxyEnabled.setAttribute('aria-pressed', isEnabled ? 'true' : 'false');
    if (isEnabled) {
      btnToggleProxyEnabled.style.background = '#059669';
      btnToggleProxyEnabled.style.color = '#ffffff';
      btnToggleProxyEnabled.style.border = '1px solid #10b981';
      btnToggleProxyEnabled.style.boxShadow = '0 0 10px rgba(16, 185, 129, 0.25)';
      btnToggleProxyEnabled.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
        <span>${activeLabel}</span>
      `;
    } else {
      btnToggleProxyEnabled.style.background = '#7f1d1d';
      btnToggleProxyEnabled.style.color = '#fecaca';
      btnToggleProxyEnabled.style.border = '1px solid #991b1b';
      btnToggleProxyEnabled.style.boxShadow = '0 0 10px rgba(153, 27, 27, 0.25)';
      btnToggleProxyEnabled.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
        </svg>
        <span>${disabledLabel}</span>
      `;
    }

    if (activeTasksWarning) {
      const runningTasks = parseInt(btnToggleProxyEnabled.dataset.runningTasks || '0', 10);
      if (!isEnabled && runningTasks > 0) {
        activeTasksWarning.style.display = 'flex';
      } else {
        activeTasksWarning.style.display = 'none';
      }
    }
  }

  if (btnToggleProxyEnabled && proxyEnabledInput) {
    btnToggleProxyEnabled.addEventListener('click', () => {
      const current = proxyEnabledInput.value === 'true';
      proxyEnabledInput.value = current ? 'false' : 'true';
      updateProxyEnabledButtonState();
    });
    updateProxyEnabledButtonState();
  }

  document.querySelectorAll('.btn-edit-proxy').forEach((btn) => {
    btn.addEventListener('click', () => {
      const proxyId = btn.getAttribute('data-proxy-id');
      const name = btn.getAttribute('data-proxy-name') || '';
      const host = btn.getAttribute('data-proxy-host') || '';
      const port = btn.getAttribute('data-proxy-port') || '8443';
      const concurrency = btn.getAttribute('data-proxy-concurrency') || '1';
      const enabled = btn.getAttribute('data-proxy-enabled') === 'true';
      const runningTasks = parseInt(btn.getAttribute('data-proxy-running-tasks') || '0', 10);

      document.getElementById('edit-proxy-id').value = proxyId;
      document.getElementById('edit-proxy-name').value = name;
      document.getElementById('edit-proxy-host').value = host;
      document.getElementById('edit-proxy-port').value = port;
      document.getElementById('edit-proxy-concurrency').value = concurrency;
      if (btnToggleProxyEnabled) {
        btnToggleProxyEnabled.dataset.runningTasks = runningTasks;
      }
      if (proxyEnabledInput) {
        proxyEnabledInput.value = enabled ? 'true' : 'false';
        updateProxyEnabledButtonState();
      }
      document.getElementById('edit-proxy-token').value = '';

      const certExpiresAt = btn.getAttribute('data-proxy-cert-expires-at') || '';
      const certExpElem = document.getElementById('edit-proxy-cert-expires-at');
      if (certExpElem) {
        certExpElem.textContent = certExpiresAt || window._t('proxy_cert_no_expiry_info', 'Non disponibile (nessuna data registrata)');
      }

      const errEl = document.getElementById('edit-proxy-error');
      if (errEl) errEl.style.display = 'none';
      const remWarningEl = document.getElementById('edit-proxy-remotes-warning');
      if (remWarningEl) remWarningEl.style.display = 'none';

      const currentRcloneEl = document.getElementById('edit-proxy-current-rclone');
      const rcloneVer = btn.getAttribute('data-proxy-rclone-version') || '';
      if (currentRcloneEl) {
        currentRcloneEl.textContent = rcloneVer || window._t('proxy_no_saved_fingerprint', '(Non rilevata)');
      }
      loadProxyRcloneDetails(proxyId, false);

      try {
        const rawRemotes = btn.getAttribute('data-proxy-remotes') || '';
      let remotesList = [];
      if (rawRemotes.startsWith('[') && rawRemotes.endsWith(']')) {
        try {
          remotesList = JSON.parse(rawRemotes);
        } catch (_) {}
      } else {
        remotesList = rawRemotes.split(',').map(s => s.trim()).filter(Boolean);
      }
        document.querySelectorAll('.edit-proxy-remote-checkbox').forEach(cb => {
          cb.checked = remotesList.includes(cb.value);
        });
        checkProxyRemotesJobConflicts(proxyId);
      } catch (_) {}
      switchProxyTab('tab-proxy-general');
      openModal('modal-edit-proxy');
    });
  });

  document.querySelectorAll('.edit-proxy-remote-checkbox').forEach(cb => {
    cb.addEventListener('change', () => {
      const pid = document.getElementById('edit-proxy-id')?.value;
      if (pid) {
        checkProxyRemotesJobConflicts(pid);
      }
    });
  });

  const saveEditBtn = document.getElementById('btn-save-edit-proxy');
  if (saveEditBtn) {
    saveEditBtn.addEventListener('click', handleSaveEdit);
  }

  // Delete Proxy Handlers
  document.querySelectorAll('.btn-delete-proxy').forEach((btn) => {
    btn.addEventListener('click', () => {
      const proxyId = btn.getAttribute('data-proxy-id');
      const name = btn.getAttribute('data-proxy-name') || '';

      document.getElementById('delete-proxy-id').value = proxyId;
      document.getElementById('delete-proxy-name').textContent = name;

      const errEl = document.getElementById('delete-proxy-error');
      if (errEl) errEl.style.display = 'none';

      const delBtn = document.getElementById('btn-confirm-delete-proxy');
      if (delBtn) {
        delBtn.disabled = false;
        if (!delBtn.dataset.originalText) {
          delBtn.dataset.originalText = delBtn.textContent.trim();
        } else {
          delBtn.textContent = delBtn.dataset.originalText;
        }
      }

      openModal('modal-delete-proxy');
    });
  });

  const confirmDeleteBtn = document.getElementById('btn-confirm-delete-proxy');
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', handleConfirmDelete);
  }

  // Retrust Proxy Handlers
  document.querySelectorAll('.btn-retrust-proxy').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const proxyId = btn.getAttribute('data-proxy-id');
      const name = btn.getAttribute('data-proxy-name') || '';
      const host = btn.getAttribute('data-proxy-host') || '';
      const port = btn.getAttribute('data-proxy-port') || '8443';
      const oldFingerprint = btn.getAttribute('data-proxy-old-fingerprint') || '';

      startRetrustWizard(proxyId, name, host, port, oldFingerprint);
    });
  });

  const confirmRetrustBtn = document.getElementById('btn-confirm-retrust-proxy');
  if (confirmRetrustBtn) {
    confirmRetrustBtn.addEventListener('click', handleConfirmRetrust);
  }

  // Renew TLS Certificate Modal Handlers
  document.querySelectorAll('.btn-renew-cert-proxy').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const proxyId = btn.getAttribute('data-proxy-id');
      const name = btn.getAttribute('data-proxy-name') || '';
      document.getElementById('renew-cert-proxy-id').value = proxyId;
      document.getElementById('renew-cert-proxy-name').textContent = name;
      const errBox = document.getElementById('renew-cert-proxy-error');
      if (errBox) errBox.style.display = 'none';
      const modal = document.getElementById('modal-renew-cert-proxy');
      if (modal) modal.classList.add('active');
    });
  });

  const btnConfirmRenewCert = document.getElementById('btn-confirm-renew-cert-proxy');
  if (btnConfirmRenewCert) {
    btnConfirmRenewCert.addEventListener('click', async () => {
      const proxyId = document.getElementById('renew-cert-proxy-id').value;
      const errBox = document.getElementById('renew-cert-proxy-error');
      if (errBox) errBox.style.display = 'none';
      btnConfirmRenewCert.disabled = true;
      btnConfirmRenewCert.textContent = window._t('status_renewing_ellipsis', 'Rinnovo in corso...');

      try {
        const res = await fetch(`/api/ui/proxies/${proxyId}/renew-cert`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken(),
          },
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || data.error || `HTTP ${res.status}`);
        }

        showToast(window._t('proxy_renew_cert_success_toast', 'Comando di rinnovo inviato con successo. Procedi a confermare il nuovo fingerprint non appena il proxy si riavvia.'), 'success');
        const modal = document.getElementById('modal-renew-cert-proxy');
        if (modal) modal.classList.remove('active');
        setTimeout(() => {
          window.location.reload();
        }, 600);
      } catch (err) {
        if (errBox) {
          errBox.textContent = err.message;
          errBox.style.display = 'block';
        }
      } finally {
        btnConfirmRenewCert.disabled = false;
        btnConfirmRenewCert.textContent = window._t('btn_renew_cert_confirm', 'Conferma Rinnovo');
      }
    });
  }

  // Listen for realtime status events to automatically reflect state changes (e.g. untrusted after cert renewal)
  window.addEventListener('embervault:realtime_status', (e) => {
    const data = e.detail;
    if (!data || !Array.isArray(data.proxies)) return;

    // Do not reload while user is interacting with an open modal
    if (document.querySelector('.modal-backdrop.active')) return;

    let needsReload = false;
    data.proxies.forEach((p) => {
      const badge = document.getElementById(`badge-proxy-${p.name}`);
      if (badge) {
        const expectedState = p.state || 'offline';
        if (!badge.classList.contains(`badge-${expectedState}`)) {
          needsReload = true;
        }
      }
    });

    if (needsReload) {
      window.location.reload();
    }
  });

  // Row and link click handlers to open edit modal on /proxies
  document.querySelectorAll('#table-proxies tr.clickable-row').forEach((row) => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('button, input, select, textarea, .btn-delete-proxy, .btn-retrust-proxy, .btn-renew-cert-proxy')) return;
      const proxyId = row.getAttribute('data-proxy-id');
      const editBtn = row.querySelector(`.btn-edit-proxy[data-proxy-id="${proxyId}"]`);
      if (editBtn) editBtn.click();
    });
  });

  // Auto-open Edit Modal if ?edit=<proxy_id> is present in URL
  const urlParams = new URLSearchParams(window.location.search);
  const editProxyId = urlParams.get('edit') || (window.location.hash.startsWith('#edit-') ? window.location.hash.slice(6) : null);
  if (editProxyId) {
    const editBtn = document.querySelector(`.btn-edit-proxy[data-proxy-id="${editProxyId}"]`);
    if (editBtn) {
      editBtn.click();
      try {
        const url = new URL(window.location.href);
        url.searchParams.delete('edit');
        if (url.hash.startsWith('#edit-')) url.hash = '';
        window.history.replaceState({ modalOpen: 'modal-edit-proxy' }, document.title, url.toString());
      } catch (_) {}
    }
  }
});

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute('content') : '';
}

async function handleProbe() {
  const host = document.getElementById('input-proxy-host').value.trim();
  const port = parseInt(document.getElementById('input-proxy-port').value, 10);
  const token = document.getElementById('input-proxy-token').value.trim();
  const probeError = document.getElementById('probe-error');
  const probeBtn = document.getElementById('btn-probe-proxy');

  if (!host || !token) {
    if (probeError) {
      probeError.textContent = window._t('err_proxy_host_token_required', 'Host e Token sono obbligatori.');
      probeError.style.display = 'block';
    }
    return;
  }

  if (probeError) probeError.style.display = 'none';
  probeBtn.disabled = true;
  probeBtn.textContent = window._t('status_verifying_ellipsis', 'Verifica in corso...');

  try {
    const res = await fetch('/api/ui/proxies/probe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      body: JSON.stringify({ host, port, token }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    // Success: Populate step 2 with detected fingerprint
    document.getElementById('display-fingerprint').textContent = data.cert_fingerprint_sha256;
    const inputFp = document.getElementById('input-proxy-fingerprint');
    inputFp.value = data.cert_fingerprint_sha256;
    inputFp.dataset.certExpiresAt = data.cert_expires_at || '';

    // Display latency / versions if present
    const metaDetails = document.getElementById('probe-meta-details');
    if (metaDetails) {
      metaDetails.textContent = `${window._t('col_latency', 'Latenza')}: ${data.latency_ms || 0} ms | Proxy v: ${data.proxy_version || 'N/A'} | RClone: ${data.rclone_version || 'N/A'}`;
    }

    // Switch steps
    document.getElementById('step-probe').style.display = 'none';
    document.getElementById('step-confirm').style.display = 'block';
    switchProxyTab('tab-register-general', document.getElementById('modal-register-proxy'));

  } catch (err) {
    if (probeError) {
      probeError.textContent = `${window._t('err_proxy_probe_prefix', 'Errore di probe: ')}${err.message}`;
      probeError.style.display = 'block';
    }
  } finally {
    probeBtn.disabled = false;
    probeBtn.textContent = window._t('btn_probe_proxy', 'Verifica Proxy (Probe)');
  }
}

async function handleRegister() {
  const name = document.getElementById('input-proxy-name').value.trim();
  const host = document.getElementById('input-proxy-host').value.trim();
  const port = parseInt(document.getElementById('input-proxy-port').value, 10);
  const token = document.getElementById('input-proxy-token').value.trim();
  const fingerprint = document.getElementById('input-proxy-fingerprint').value.trim();
  const registerError = document.getElementById('register-error');
  const confirmBtn = document.getElementById('btn-confirm-register');

  if (!name) {
    if (registerError) {
      registerError.textContent = window._t('err_proxy_unique_name_required', 'Inserisci un nome univoco per il proxy.');
      registerError.style.display = 'block';
    }
    return;
  }

  confirmBtn.disabled = true;
  confirmBtn.textContent = window._t('status_registering_ellipsis', 'Registrazione in corso...');

  try {
    const res = await fetch('/api/ui/proxies/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      body: JSON.stringify({
        name,
        host,
        port,
        token,
        cert_fingerprint_sha256: fingerprint,
        cert_expires_at: document.getElementById('input-proxy-fingerprint').dataset.certExpiresAt || null,
        reachable_remote_ids: Array.from(
          document.querySelectorAll('input[name="register_reachable_remote_ids"]:checked')
        ).map((cb) => cb.value),
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    showToast(window._t('proxy_registered_toast', 'Proxy registrato con successo!'));
    closeModal('modal-register-proxy');
    setTimeout(() => window.location.reload(), 1000);

  } catch (err) {
    if (registerError) {
      registerError.textContent = `${window._t('err_proxy_register_prefix', 'Errore di registrazione: ')}${err.message}`;
      registerError.style.display = 'block';
      registerError.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(err.message, 'error');
    confirmBtn.disabled = false;
    confirmBtn.textContent = window._t('btn_confirm_register', 'Conferma Fingerprint & Registra');
  }
}

function getRemoteJobUsage() {
  try {
    const el = document.getElementById('remote-job-usage-data');
    if (el && el.textContent) {
      return JSON.parse(el.textContent);
    }
  } catch (_) {}
  return {};
}

function checkProxyRemotesJobConflicts(proxyId) {
  const usage = getRemoteJobUsage();
  const warningEl = document.getElementById('edit-proxy-remotes-warning');
  const checkboxes = document.querySelectorAll('.edit-proxy-remote-checkbox');
  const conflicts = [];

  checkboxes.forEach((cb) => {
    const card = cb.closest('.edit-proxy-remote-card') || cb.parentElement;
    const remoteId = cb.value;
    const remoteName = cb.dataset.remoteName || remoteId;
    const isChecked = cb.checked;

    const jobsForRemote = usage[remoteId] || [];
    const activeJobs = jobsForRemote.filter((j) => {
      const assigned = j.assigned_proxy_ids || [];
      return assigned.length === 0 || assigned.includes(proxyId);
    });

    if (activeJobs.length > 0) {
      if (!isChecked) {
        if (card) {
          card.style.borderColor = 'var(--status-danger, #ef4444)';
          card.style.backgroundColor = 'rgba(239, 68, 68, 0.08)';
        }
        activeJobs.forEach((job) => {
          conflicts.push({ remoteName, jobName: job.job_name });
        });
      } else {
        if (card) {
          card.style.borderColor = 'var(--color-border)';
          card.style.backgroundColor = 'var(--color-bg-base)';
        }
      }
    } else {
      if (card) {
        card.style.borderColor = 'var(--color-border)';
        card.style.backgroundColor = 'var(--color-bg-base)';
      }
    }
  });

  if (warningEl) {
    if (conflicts.length > 0) {
      const details = conflicts.map(c => `<strong>${c.remoteName}</strong> (<em>${c.jobName}</em>)`).join(', ');
      const tpl = window._t(
        'proxy_remotes_job_conflict_warning',
        '⚠️ Attenzione: questo proxy è attivo per job che richiedono i remote deselezionati: {details}. Rimuovendo l\'affinità il salvataggio verrà bloccato o i job non potranno operare.'
      );
      warningEl.innerHTML = tpl.replace('{details}', details);
      warningEl.style.display = 'block';
    } else {
      warningEl.style.display = 'none';
      warningEl.innerHTML = '';
    }
  }

  return conflicts;
}

async function handleSaveEdit() {
  const proxyId = document.getElementById('edit-proxy-id').value;
  const name = document.getElementById('edit-proxy-name').value.trim();
  const host = document.getElementById('edit-proxy-host').value.trim();
  const port = parseInt(document.getElementById('edit-proxy-port').value, 10);
  const concurrency = parseInt(document.getElementById('edit-proxy-concurrency').value, 10) || 1;
  const isEnabled = document.getElementById('edit-proxy-enabled').value === 'true';
  const token = document.getElementById('edit-proxy-token').value.trim();
  const errorEl = document.getElementById('edit-proxy-error');
  const saveBtn = document.getElementById('btn-save-edit-proxy');

  if (!name || !host) {
    if (errorEl) {
      errorEl.textContent = window._t('err_proxy_name_host_required', 'Nome e Host sono obbligatori.');
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return;
  }

  if (isNaN(port) || port < 1 || port > 65535) {
    if (errorEl) {
      errorEl.textContent = window._t('err_proxy_invalid_port', 'La porta deve essere un numero valido tra 1 e 65535.');
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return;
  }

  if (token && token.length < 32) {
    if (errorEl) {
      errorEl.textContent = window._t('err_proxy_token_min_length', 'Il nuovo token deve essere di almeno 32 caratteri.');
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    return;
  }

  const conflicts = checkProxyRemotesJobConflicts(proxyId);
  if (conflicts.length > 0) {
    const first = conflicts[0];
    const tpl = window._t(
      'proxy_cannot_remove_remote_job_conflict',
      "Impossibile rimuovere il remote '{remote}': è richiesto dal job '{job}' per cui questo proxy è attivo."
    );
    const msg = tpl.replace('{remote}', first.remoteName).replace('{job}', first.jobName);
    if (errorEl) {
      errorEl.textContent = msg;
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(msg, 'error');
    switchProxyTab('tab-proxy-remotes');
    return;
  }

  if (errorEl) errorEl.style.display = 'none';
  if (!saveBtn.dataset.originalText) {
    saveBtn.dataset.originalText = saveBtn.textContent.trim();
  }
  saveBtn.disabled = true;
  saveBtn.textContent = window._t('status_saving_in_progress', 'Salvataggio in corso...');

  try {
    const reachable_remote_ids = Array.from(
      document.querySelectorAll('.edit-proxy-remote-checkbox:checked')
    ).map((cb) => cb.value);
    const payload = {
      name,
      host,
      port,
      max_concurrent_tasks: concurrency,
      is_enabled: isEnabled,
      reachable_remote_ids,
    };
    if (token) {
      payload.token = token;
    }

    const res = await fetch(`/api/ui/proxies/${proxyId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    if (data.warning) {
      showToast(data.warning, 'warning');
      closeModal('modal-edit-proxy');
      setTimeout(() => window.location.reload(), 2500);
    } else {
      showToast(window._t('proxy_updated_toast', 'Proxy aggiornato con successo!'));
      closeModal('modal-edit-proxy');
      setTimeout(() => window.location.reload(), 700);
    }
  } catch (err) {
    if (errorEl) {
      errorEl.textContent = `${window._t('err_saving_prefix', 'Errore di salvataggio: ')}${err.message}`;
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(err.message, 'error');
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = saveBtn.dataset.originalText || window._t('btn_save_changes', 'Salva Modifiche');
  }
}

async function handleConfirmDelete() {
  const proxyId = document.getElementById('delete-proxy-id').value;
  const errorEl = document.getElementById('delete-proxy-error');
  const deleteBtn = document.getElementById('btn-confirm-delete-proxy');

  if (!proxyId) return;

  if (errorEl) errorEl.style.display = 'none';
  if (!deleteBtn.dataset.originalText) {
    deleteBtn.dataset.originalText = deleteBtn.textContent.trim();
  }
  deleteBtn.disabled = true;
  deleteBtn.textContent = window._t('status_deleting_in_progress', 'Eliminazione in corso...');

  try {
    const res = await fetch(`/api/ui/proxies/${proxyId}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    showToast(window._t('proxy_deleted_toast', 'Proxy eliminato con successo!'));
    closeModal('modal-delete-proxy');
    setTimeout(() => window.location.reload(), 700);
  } catch (err) {
    if (errorEl) {
      errorEl.textContent = `${window._t('err_deleting_prefix', 'Errore di eliminazione: ')}${err.message}`;
      errorEl.style.display = 'block';
      errorEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    showToast(err.message, 'error');
    deleteBtn.disabled = false;
    deleteBtn.textContent = deleteBtn.dataset.originalText || window._t('btn_delete_permanently', 'Elimina Definitivamente');
  }
}

async function startRetrustWizard(proxyId, name, host, port, oldFingerprint) {
  document.getElementById('retrust-proxy-id').value = proxyId;
  document.getElementById('retrust-proxy-name').textContent = name;
  document.getElementById('retrust-proxy-endpoint').textContent = `${host}:${port}`;
  document.getElementById('retrust-old-fingerprint').textContent = oldFingerprint || window._t('proxy_no_saved_fingerprint', '(Nessuna impronta salvata)');
  document.getElementById('retrust-new-fingerprint').textContent = '';
  document.getElementById('retrust-new-fingerprint-hidden').value = '';

  const stepProbing = document.getElementById('retrust-step-probing');
  const stepConfirm = document.getElementById('retrust-step-confirm');
  const errorEl = document.getElementById('retrust-error');
  const confirmBtn = document.getElementById('btn-confirm-retrust-proxy');

  if (stepProbing) stepProbing.style.display = 'block';
  if (stepConfirm) stepConfirm.style.display = 'none';
  if (errorEl) errorEl.style.display = 'none';
  if (confirmBtn) {
    confirmBtn.style.display = 'none';
    confirmBtn.disabled = false;
    confirmBtn.textContent = window._t('proxy_retrust_accept_btn', 'Accetta Nuovo Fingerprint & Ristabilisci Fiducia');
  }

  openModal('modal-retrust-proxy');

  try {
    const res = await fetch(`/api/ui/proxies/${proxyId}/retrust-probe`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    const newFingerprint = data.new_fingerprint;
    document.getElementById('retrust-new-fingerprint').textContent = newFingerprint;
    const hiddenFpEl = document.getElementById('retrust-new-fingerprint-hidden');
    hiddenFpEl.value = newFingerprint;
    hiddenFpEl.dataset.certExpiresAt = data.cert_expires_at || '';

    if (stepProbing) stepProbing.style.display = 'none';
    if (stepConfirm) stepConfirm.style.display = 'block';
    if (confirmBtn) confirmBtn.style.display = 'inline-block';
  } catch (err) {
    if (stepProbing) stepProbing.style.display = 'none';
    if (errorEl) {
      errorEl.textContent = `${window._t('err_proxy_cannot_query_prefix', 'Impossibile interrogare il proxy: ')}${err.message}`;
      errorEl.style.display = 'block';
    }
  }
}

async function handleConfirmRetrust() {
  const proxyId = document.getElementById('retrust-proxy-id').value;
  const newFingerprint = document.getElementById('retrust-new-fingerprint-hidden').value.trim();
  const errorEl = document.getElementById('retrust-error');
  const confirmBtn = document.getElementById('btn-confirm-retrust-proxy');

  if (!proxyId || !newFingerprint) return;

  if (errorEl) errorEl.style.display = 'none';
  confirmBtn.disabled = true;
  confirmBtn.textContent = window._t('proxy_retrust_restoring_ellipsis', 'Ristabilimento fiducia in corso...');

  try {
    const certExpiresAt = document.getElementById('retrust-new-fingerprint-hidden').dataset.certExpiresAt || null;
    const res = await fetch(`/api/ui/proxies/${proxyId}/retrust-confirm`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
      body: JSON.stringify({ cert_fingerprint_sha256: newFingerprint, cert_expires_at: certExpiresAt }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    showToast(window._t('proxy_retrust_restored_toast', 'Fiducia nel proxy ristabilita con successo!'));
    closeModal('modal-retrust-proxy');
    setTimeout(() => window.location.reload(), 700);
  } catch (err) {
    if (errorEl) {
      errorEl.textContent = `${window._t('err_saving_colon_prefix', 'Errore durante il salvataggio: ')}${err.message}`;
      errorEl.style.display = 'block';
    }
    confirmBtn.disabled = false;
    confirmBtn.textContent = window._t('proxy_retrust_accept_btn', 'Accetta Nuovo Fingerprint & Ristabilisci Fiducia');
  }
}

  // ============================================================
  // Proxy Modal Tabs Handlers (Generale, Remote, RClone)
  // ============================================================
  function switchProxyTab(tabId, container) {
    const root = container || (document.getElementById(tabId)?.closest('.modal-card') || document);
    const buttons = root.querySelectorAll('.proxy-tab-btn');
    const panes = root.querySelectorAll('.proxy-tab-pane');

    buttons.forEach((btn) => {
      const isActive = btn.dataset.tab === tabId;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });
    panes.forEach((pane) => {
      const isActive = pane.id === tabId;
      pane.classList.toggle('active', isActive);
      pane.style.display = isActive ? 'block' : 'none';
    });
  }

  document.querySelectorAll('.proxy-tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchProxyTab(btn.dataset.tab, btn.closest('.modal-card'));
    });
  });

  // ============================================================
  // RClone Version Management Handlers
  // ============================================================
  const btnCheckRclone = document.getElementById('btn-check-rclone-update');
  const btnUpgradeLatest = document.getElementById('btn-upgrade-rclone-latest');
  const btnUpgradeSelect = document.getElementById('btn-upgrade-rclone-version');
  const selectRcloneVer = document.getElementById('select-rclone-version');
  const statusBadge = document.getElementById('edit-proxy-rclone-status-badge');
  const latestCard = document.getElementById('rclone-latest-update-card');
  const latestAvailText = document.getElementById('rclone-latest-avail-text');
  const progressBox = document.getElementById('rclone-upgrade-progress');
  const progressText = document.getElementById('rclone-upgrade-progress-text');

  if (selectRcloneVer && btnUpgradeSelect) {
    selectRcloneVer.addEventListener('change', () => {
      btnUpgradeSelect.disabled = !selectRcloneVer.value;
    });
  }

  if (btnCheckRclone) {
    btnCheckRclone.addEventListener('click', () => {
      const proxyId = document.getElementById('edit-proxy-id').value;
      if (proxyId) {
        loadProxyRcloneDetails(proxyId, true);
      }
    });
  }

  if (btnUpgradeLatest) {
    btnUpgradeLatest.addEventListener('click', () => {
      const proxyId = document.getElementById('edit-proxy-id').value;
      const target = btnUpgradeLatest.dataset.targetVersion || 'latest';
      if (proxyId) {
        performRcloneUpgrade(proxyId, target);
      }
    });
  }

  if (btnUpgradeSelect) {
    btnUpgradeSelect.addEventListener('click', () => {
      const proxyId = document.getElementById('edit-proxy-id').value;
      const target = selectRcloneVer ? selectRcloneVer.value : '';
      if (proxyId && target) {
        performRcloneUpgrade(proxyId, target);
      }
    });
  }

  async function loadProxyRcloneDetails(proxyId, forceRefresh) {
    if (!statusBadge) return;

    statusBadge.innerHTML = `
      <span class="badge badge-neutral" style="display: inline-flex; align-items: center; gap: 6px;">
        <span class="spinner" style="width: 10px; height: 10px; border: 2px solid rgba(255,255,255,0.2); border-top-color: currentColor; border-radius: 50%; animation: spin 1s linear infinite;"></span>
        ${window._t('status_checking_updates', 'Verifica aggiornamenti in corso...')}
      </span>
    `;

    if (latestCard) latestCard.style.display = 'none';
    if (btnUpgradeSelect) btnUpgradeSelect.disabled = true;

    try {
      const res = await fetch(`/api/ui/proxies/${proxyId}/rclone/status?refresh=${forceRefresh ? 'true' : 'false'}`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || `HTTP ${res.status}`);
      }

      const currentRcloneEl = document.getElementById('edit-proxy-current-rclone');
      if (currentRcloneEl) {
        currentRcloneEl.textContent = data.installed_version || '-';
      }

      // Populate combobox
      if (selectRcloneVer) {
        const currentSelected = selectRcloneVer.value;
        selectRcloneVer.innerHTML = `<option value="">${window._t('proxy_rclone_select_placeholder', '-- Seleziona versione --')}</option>`;
        (data.versions || []).forEach((ver) => {
          const opt = document.createElement('option');
          opt.value = ver;
          const isLatest = ver === data.latest_version;
          opt.textContent = `v${ver}` + (isLatest ? ` (${window._t('latest_label', 'Ultima')})` : '');
          selectRcloneVer.appendChild(opt);
        });
        if (currentSelected && selectRcloneVer.querySelector(`option[value="${currentSelected}"]`)) {
          selectRcloneVer.value = currentSelected;
          if (btnUpgradeSelect) btnUpgradeSelect.disabled = false;
        }
      }

      // Status badge and latest update card
      if (data.update_available) {
        statusBadge.innerHTML = `
          <span class="badge badge-warning" style="display: inline-flex; align-items: center; gap: 6px; background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3);">
            <span class="badge-dot" style="background-color: #f59e0b;"></span>
            ${window._t('status_update_available', 'Aggiornamento disponibile')}
          </span>
        `;
        if (latestCard && latestAvailText) {
          const tmpl = window._t('rclone_update_avail_text', 'È disponibile la nuova versione {version} (installata: {installed})');
          latestAvailText.textContent = tmpl.replace('{version}', 'v' + data.latest_version).replace('{installed}', 'v' + data.installed_version);
          if (btnUpgradeLatest) {
            btnUpgradeLatest.dataset.targetVersion = data.latest_version;
            btnUpgradeLatest.textContent = window._t('btn_upgrade_rclone_latest', 'Aggiorna');
          }
          latestCard.style.display = 'flex';
        }
      } else {
        statusBadge.innerHTML = `
          <span class="badge badge-online" style="display: inline-flex; align-items: center; gap: 6px;">
            <span class="badge-dot" style="background-color: #10b981;"></span>
            ${window._t('status_up_to_date', "Aggiornato all'ultima versione")}
          </span>
        `;
        if (latestCard) latestCard.style.display = 'none';
      }
    } catch (err) {
      statusBadge.innerHTML = `
        <span class="badge badge-offline" style="font-size: 0.78rem;">
          ${err.message}
        </span>
      `;
    }
  }

  async function performRcloneUpgrade(proxyId, targetVersion) {
    if (!proxyId || !targetVersion) return;

    if (progressBox) progressBox.style.display = 'flex';
    if (progressText) {
      progressText.textContent = `${window._t('rclone_upgrading_msg', 'Download e installazione di RClone in corso sul proxy...')} (v${targetVersion})`;
    }
    if (btnUpgradeLatest) btnUpgradeLatest.disabled = true;
    if (btnUpgradeSelect) btnUpgradeSelect.disabled = true;
    if (btnCheckRclone) btnCheckRclone.disabled = true;

    try {
      const res = await fetch(`/api/ui/proxies/${proxyId}/rclone/upgrade`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ version: targetVersion }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || `HTTP ${res.status}`);
      }

      showToast(data.message || window._t('rclone_upgrade_success_toast', 'RClone aggiornato con successo sul proxy!'), 'success');

      // Update row data attribute and row text in table
      const row = document.querySelector(`tr[data-proxy-id="${proxyId}"]`);
      if (row) {
        row.setAttribute('data-proxy-rclone-version', data.version || targetVersion);
        const rcloneSpan = row.querySelector('.proxy-row-rclone-ver');
        if (rcloneSpan) {
          rcloneSpan.textContent = `(RClone: ${data.version || targetVersion})`;
        }
      }
      const editBtn = document.querySelector(`.btn-edit-proxy[data-proxy-id="${proxyId}"]`);
      if (editBtn) {
        editBtn.setAttribute('data-proxy-rclone-version', data.version || targetVersion);
      }

      await loadProxyRcloneDetails(proxyId, true);
    } catch (err) {
      showToast(`${window._t('rclone_upgrade_failed_toast', "Errore durante l'aggiornamento di RClone")}: ${err.message}`, 'danger');
    } finally {
      if (progressBox) progressBox.style.display = 'none';
      if (btnUpgradeLatest) btnUpgradeLatest.disabled = false;
      if (btnUpgradeSelect && selectRcloneVer && selectRcloneVer.value) btnUpgradeSelect.disabled = false;
      if (btnCheckRclone) btnCheckRclone.disabled = false;
    }
  }

