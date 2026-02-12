import React, { useState } from 'react'

export default function AddBook({ onAdd }) {
  const [title, setTitle] = useState('')
  const [author, setAuthor] = useState('')
  const [genre, setGenre] = useState('')
  const [isbn, setIsbn] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setError('')
    if (!title.trim() || !author.trim() || !isbn.trim()) {
      setError('Titel, Autor und ISBN sind erforderlich')
      return
    }
    setLoading(true)
    try {
      const token = localStorage.getItem('token')
      const res = await fetch('http://localhost:5000/books', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ title, author, genre, isbn })
      })
      if (res.status === 409) {
        setError('Ein Buch mit dieser ISBN existiert bereits')
        setLoading(false)
        return
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        setError(err.error || 'Fehler beim Hinzufügen')
        setLoading(false)
        return
      }
      const data = await res.json()
      setTitle('')
      setAuthor('')
      setGenre('')
      setIsbn('')
      setLoading(false)
      onAdd && onAdd(data)
    } catch (err) {
      setError('Netzwerkfehler')
      setLoading(false)
    }
  }

  return (
    <form className="filter-form" onSubmit={submit} style={{ marginBottom: 12 }}>
      <div className="field">
        <label>Titel</label>
        <input value={title} onChange={e => setTitle(e.target.value)} />
      </div>
      <div className="field">
        <label>Autor</label>
        <input value={author} onChange={e => setAuthor(e.target.value)} />
      </div>
      <div className="field">
        <label>Genre</label>
        <input value={genre} onChange={e => setGenre(e.target.value)} />
      </div>
      <div className="field">
        <label>ISBN</label>
        <input value={isbn} onChange={e => setIsbn(e.target.value)} />
      </div>
      <div className="actions">
        <button type="submit" disabled={loading}>{loading ? '...' : 'Buch hinzufügen'}</button>
      </div>
      {error && <p className="api-msg">{error}</p>}
    </form>
  )
}
