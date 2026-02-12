import { useEffect, useState } from 'react'
import Filter from './components/Filter'
import BookList from './components/BookList'
import './App.css'
import React, { useState } from 'react'

const sampleBooks = [
  { id: 1, title: 'Der kleine Prinz', author: 'Antoine de Saint-Exupéry', genre: 'Kinderbuch', isbn: '978315000001' },
  { id: 2, title: 'Faust', author: 'Johann Wolfgang von Goethe', genre: 'Drama', isbn: '978315000002' },
  { id: 3, title: 'Clean Code', author: 'Robert C. Martin', genre: 'Programmierung', isbn: '9780132350884' },
  { id: 4, title: 'Eloquent JavaScript', author: 'Marijn Haverbeke', genre: 'Programmierung', isbn: '9781593279509' },
  { id: 5, title: 'Die Verwandlung', author: 'Franz Kafka', genre: 'Novelle', isbn: '978315000005' },
]

function App() {
  const [message, setMessage] = useState('')
  const [books] = useState(sampleBooks)
  const [filters, setFilters] = useState({ title: '', author: '', genre: '', isbn: '' })

  useEffect(() => {
    fetch('http://localhost:5000/')
      .then(res => res.text())
      .then(data => setMessage(data))
      .catch(() => setMessage('Backend nicht erreichbar'))
  }, [])

  function handleFilterChange(name, value) {
    setFilters(prev => ({ ...prev, [name]: value }))
  }

  function clearFilters() {
    setFilters({ title: '', author: '', genre: '', isbn: '' })
  }

  const filtered = books.filter(b => {
    if (filters.title && !b.title.toLowerCase().includes(filters.title.toLowerCase())) return false
    if (filters.author && !b.author.toLowerCase().includes(filters.author.toLowerCase())) return false
    if (filters.genre && !b.genre.toLowerCase().includes(filters.genre.toLowerCase())) return false
    if (filters.isbn && !b.isbn.toLowerCase().includes(filters.isbn.toLowerCase())) return false
    return true
  })

  return (
    <div className="app-container">
      <div className="topbar">
        <header className="topbar-header">
          <h1>Bibliotheksverwaltung</h1>
        </header>

        <div className="topbar-filters">
          <Filter filters={filters} onChange={handleFilterChange} onClear={clearFilters} />
        </div>
      </div>

      <main className="content">
        <section className="list">
          <BookList books={filtered} />
        </section>
      </main>
    </div>
  )
}

export default App