import React, { useState } from 'react'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [error, setError] = useState('')

  async function submit(e) {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('Bitte Benutzer und Passwort eingeben')
      return
    }
    setError('')
    try {
      const res = await fetch('http://localhost:5000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setError(err.error || 'Login fehlgeschlagen')
        return
      }
      const data = await res.json()
      // data: { token, user }
      onLogin(data)
    } catch (err) {
      setError('Netzwerkfehler')
    }
  }

  async function register(e) {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('Bitte Benutzer und Passwort eingeben')
      return
    }
    setError('')
    try {
      const payload = { username, password }
      // only send role when user explicitly chose admin during registration
      if (isAdmin) payload.role = 'admin'
      const res = await fetch('http://localhost:5000/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setError(err.error || 'Registrierung fehlgeschlagen')
        return
      }
      const data = await res.json()
      onLogin(data)
    } catch (err) {
      setError('Netzwerkfehler')
    }
  }

  return (
    <div className="app-container">
      <h1>Login</h1>
      <form className="filter-form" onSubmit={submit}>
        <div className="field">
          <label>Benutzer</label>
          <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Benutzername" />
        </div>

        <div className="field">
          <label>Passwort</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Passwort" />
        </div>

        <div className="field" style={{ alignItems: 'center', display: 'flex', gap: '0.5rem' }}>
          <input id="adminCheck" type="checkbox" checked={isAdmin} onChange={e => setIsAdmin(e.target.checked)} />
          <label htmlFor="adminCheck">Als Admin registrieren</label>
        </div>

        <div className="actions">
          <button type="submit">Login</button>
          <button type="button" onClick={register}>Registrieren</button>
        </div>

        {error && <p className="api-msg">{error}</p>}
      </form>
    </div>
  )
}