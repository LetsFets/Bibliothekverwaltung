import React, { useState } from 'react'

function Settings({ token, onChangePassword, onDeleteAccount, onLogout, onClose }) {
  const [tab, setTab] = useState('password') // 'password' or 'delete'
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('')
  const [deletePassword, setDeletePassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  async function handleChangePassword(e) {
    e.preventDefault()
    if (!oldPassword || !newPassword) {
      setMessage('Alle Felder erforderlich')
      return
    }
    if (newPassword !== newPasswordConfirm) {
      setMessage('Neue Passwörter stimmen nicht überein')
      return
    }
    if (newPassword.length < 3) {
      setMessage('Passwort muss mindestens 3 Zeichen lang sein')
      return
    }

    setLoading(true)
    setMessage('')
    try {
      const res = await fetch('http://localhost:5000/user/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ oldPassword, newPassword })
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setMessage(err.error || 'Passwort ändern fehlgeschlagen')
      } else {
        setMessage('Passwort erfolgreich geändert')
        setOldPassword('')
        setNewPassword('')
        setNewPasswordConfirm('')
        onChangePassword && onChangePassword()
        setTimeout(() => {
          setMessage('')
        }, 3000)
      }
    } catch (err) {
      setMessage('Netzwerkfehler')
    } finally {
      setLoading(false)
    }
  }

  async function handleDeleteAccount(e) {
    e.preventDefault()
    if (!deletePassword) {
      setMessage('Passwort erforderlich')
      return
    }
    if (!window.confirm('Möchten Sie Ihren Account wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.')) {
      return
    }

    setLoading(true)
    setMessage('')
    try {
      const res = await fetch('http://localhost:5000/user/account', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ password: deletePassword })
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setMessage(err.error || 'Account löschen fehlgeschlagen')
      } else {
        setMessage('Account erfolgreich gelöscht')
        setTimeout(() => {
          onDeleteAccount && onDeleteAccount()
        }, 1500)
      }
    } catch (err) {
      setMessage('Netzwerkfehler')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="settings-modal">
      <div className="settings-container">
        <div className="settings-header">
          <h2>Einstellungen</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="settings-tabs">
          <button
            className={`tab-btn ${tab === 'password' ? 'active' : ''}`}
            onClick={() => {
              setTab('password')
              setMessage('')
            }}
          >
            Passwort ändern
          </button>
          <button
            className={`tab-btn ${tab === 'delete' ? 'active' : ''}`}
            onClick={() => {
              setTab('delete')
              setMessage('')
            }}
          >
            Account löschen
          </button>
        </div>

        {tab === 'password' && (
          <form onSubmit={handleChangePassword} className="settings-form">
            <div className="form-group">
              <label htmlFor="oldPassword">Altes Passwort</label>
              <input
                id="oldPassword"
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className="form-group">
              <label htmlFor="newPassword">Neues Passwort</label>
              <input
                id="newPassword"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className="form-group">
              <label htmlFor="newPasswordConfirm">Passwort bestätigen</label>
              <input
                id="newPasswordConfirm"
                type="password"
                value={newPasswordConfirm}
                onChange={(e) => setNewPasswordConfirm(e.target.value)}
                disabled={loading}
              />
            </div>
            {message && <div className="settings-message">{message}</div>}
            <button type="submit" disabled={loading}>
              {loading ? 'Wird gespeichert...' : 'Passwort ändern'}
            </button>
          </form>
        )}

        {tab === 'delete' && (
          <form onSubmit={handleDeleteAccount} className="settings-form">
            <div className="settings-warning">
              ⚠️ Löschen Sie Ihren Account
            </div>
            <p className="settings-info">
              Dies löscht Ihren Account und alle zugehörigen Reservierungen permanent. Diese Aktion kann nicht rückgängig gemacht werden.
            </p>
            <div className="form-group">
              <label htmlFor="deletePassword">Passwort zur Bestätigung</label>
              <input
                id="deletePassword"
                type="password"
                value={deletePassword}
                onChange={(e) => setDeletePassword(e.target.value)}
                disabled={loading}
                placeholder="Geben Sie Ihr Passwort ein"
              />
            </div>
            {message && <div className="settings-message">{message}</div>}
            <button type="submit" disabled={loading} className="delete-btn">
              {loading ? 'Wird gelöscht...' : 'Account jetzt löschen'}
            </button>
          </form>
        )}

        <div className="settings-footer">
          <button className="logout-btn" onClick={onLogout}>
            Abmelden
          </button>
        </div>
      </div>
    </div>
  )
}

export default Settings
