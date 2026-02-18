
import React, { useEffect, useState } from 'react'
import Filter from './components/Filter'
import BookList from './components/BookList'
import AddBook from './components/AddBook'
import Login from './components/Login'
import Settings from './components/Settings'
import './App.css'

// books will be loaded from backend after login

function App() {
  const [message, setMessage] = useState('')
  const [books, setBooks] = useState([])
  const [filters, setFilters] = useState({ title: '', author: '', genre: '', isbn: '' })
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [user, setUser] = useState(null)
  const [showSettings, setShowSettings] = useState(false)

  useEffect(() => {
    // initial API message
    fetch('http://localhost:5000/')
      .then(res => res.text())
      .then(data => setMessage(data))
      .catch(() => setMessage('Backend nicht erreichbar'))

    // restore session
    const token = localStorage.getItem('token')
    const userStr = localStorage.getItem('user')
    if (token && userStr) {
      try {
        const u = JSON.parse(userStr)
        setUser(u)
        setIsAuthenticated(true)
        fetchBooks()
      } catch (e) {
        console.warn('Failed to parse user from storage')
      }
    }
  }, [])

  function handleFilterChange(name, value) {
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  function clearFilters() {
    setFilters({ title: '', author: '', genre: '', isbn: '' })
  }

  async function fetchBooks() {
    try {
      const res = await fetch('http://localhost:5000/books')
      if (!res.ok) return
      const data = await res.json()
      setBooks(data)
    } catch (err) {
      console.error('Fetch books failed', err)
    }
  }

  function requireToken() {
    const token = localStorage.getItem('token')
    if (!token) {
      alert('Bitte erneut einloggen')
      handleLogout()
      return null
    }
    return token
  }

  function handleAuthFailure(res) {
    if (res.status === 401) {
      alert('Bitte erneut einloggen')
      handleLogout()
      return true
    }
    return false
  }

  async function handleReserve(book) {
    try {
      const token = requireToken()
      if (!token) return
      const res = await fetch(`http://localhost:5000/books/${book.id}/reserve`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (handleAuthFailure(res)) return
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Reservierung fehlgeschlagen')
        return
      }
      await res.json()
      fetchBooks()
    } catch (err) {
      alert('Netzwerkfehler')
    }
  }

  async function handleBorrow(book) {
    try {
      const token = requireToken()
      if (!token) return
      const res = await fetch(`http://localhost:5000/books/${book.id}/borrow`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (handleAuthFailure(res)) return
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Ausleihe fehlgeschlagen')
        return
      }
      await res.json()
      fetchBooks()
    } catch (err) {
      alert('Netzwerkfehler')
    }
  }

  async function handleReturn(book) {
    try {
      const token = requireToken()
      if (!token) return
      const res = await fetch(`http://localhost:5000/books/${book.id}/return`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (handleAuthFailure(res)) return
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Rueckgabe fehlgeschlagen')
        return
      }
      await res.json()
      fetchBooks()
    } catch (err) {
      alert('Netzwerkfehler')
    }
  }

  async function handleUnreserve(book) {
    try {
      const token = requireToken()
      if (!token) return
      const res = await fetch(`http://localhost:5000/books/${book.id}/unreserve`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (handleAuthFailure(res)) return
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Aufheben fehlgeschlagen')
        return
      }
      await res.json()
      fetchBooks()
    } catch (err) {
      alert('Netzwerkfehler')
    }
  }

  async function handleUpdateBook(id, updates) {
    try {
      const token = requireToken()
      if (!token) return false
      const res = await fetch(`http://localhost:5000/books/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(updates)
      })
      if (handleAuthFailure(res)) return false
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Speichern fehlgeschlagen')
        return false
      }
      await res.json()
      fetchBooks()
      return true
    } catch (err) {
      alert('Netzwerkfehler')
      return false
    }
  }

  function handleLogin(data) {
    // data: { token, user }
    localStorage.setItem('token', data.token)
    localStorage.setItem('user', JSON.stringify(data.user))
    setUser(data.user)
    setIsAuthenticated(true)
    fetchBooks()
  }

  function handleLogout() {
    setUser(null)
    setIsAuthenticated(false)
    setBooks([])
    localStorage.removeItem('token')
    localStorage.removeItem('user')
  }

  const getSafeString = (val) => {
    if (!val) return ''
    return String(val).toLowerCase()
  }

  const filtered = books.filter(b => {
    if (filters.title && !getSafeString(b.title).includes(filters.title.toLowerCase())) return false
    if (filters.author && !getSafeString(b.author).includes(filters.author.toLowerCase())) return false
    if (filters.genre && !getSafeString(b.genre).includes(filters.genre.toLowerCase())) return false
    if (filters.isbn && !getSafeString(b.isbn).includes(filters.isbn.toLowerCase())) return false
    return true
  })

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />
  }

  

  return (
    <div className="app-container">
      <div className="topbar">
        <header className="topbar-header">
          <h1>Bibliotheksverwaltung</h1>
          <div>
            {user && <span style={{ marginRight: 10 }}>Angemeldet als {user.username}</span>}
            {user && (
              <button onClick={() => setShowSettings(true)}>
                Einstellungen
              </button>
            )}
          </div>
        </header>

        <div className="topbar-filters">
          {user && user.role === 'admin' && (
            <AddBook onAdd={() => fetchBooks()} />
          )}
          <Filter filters={filters} onChange={handleFilterChange} onClear={clearFilters} />
        </div>
      </div>

      <main className="content">
        <section className="list">
          <p className="api-msg">{message}</p>
          <BookList
            books={filtered}
            isAdmin={user && user.role === 'admin'}
            onDelete={() => fetchBooks()}
            onReserve={handleReserve}
            onUnreserve={handleUnreserve}
            currentUser={user}
            onBorrow={handleBorrow}
            onReturn={handleReturn}
            onUpdate={handleUpdateBook}
          />
        </section>
      </main>

      {showSettings && (
        <Settings
          token={localStorage.getItem('token')}
          onChangePassword={() => {
            // Keep user logged in after password change
          }}
          onDeleteAccount={() => {
            // User deleted their account, logout
            handleLogout()
          }}
          onLogout={() => {
            // User logged out from settings
            setShowSettings(false)
            handleLogout()
          }}
          onClose={() => setShowSettings(false)}
        />
      )}
    </div>
  )
}

export default App
