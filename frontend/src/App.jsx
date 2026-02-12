
import React, { useEffect, useState } from 'react'
import Filter from './components/Filter'
import BookList from './components/BookList'
import AddBook from './components/AddBook'
import Login from './components/Login'
import './App.css'

// books will be loaded from backend after login

function App() {
  const [message, setMessage] = useState('')
  const [books, setBooks] = useState([])
  const [filters, setFilters] = useState({ title: '', author: '', genre: '', isbn: '' })
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [user, setUser] = useState(null)

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

  const filtered = books.filter(b => {
    if (filters.title && !b.title.toLowerCase().includes(filters.title.toLowerCase())) return false
    if (filters.author && !b.author.toLowerCase().includes(filters.author.toLowerCase())) return false
    if (filters.genre && !b.genre.toLowerCase().includes(filters.genre.toLowerCase())) return false
    if (filters.isbn && !b.isbn.toLowerCase().includes(filters.isbn.toLowerCase())) return false
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
            <button onClick={handleLogout}>Logout</button>
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
          <BookList books={filtered} isAdmin={user && user.role === 'admin'} onDelete={() => fetchBooks()} />
        </section>
      </main>
    </div>
  )
}

export default App
