import React, { useState } from 'react'
import BookStatus from './BookStatus'

export default function BookList({ books, isAdmin, onDelete, onReserve, onUnreserve, currentUser, onBorrow, onReturn, onUpdate }) {
  const [editingId, setEditingId] = useState(null)
  const [editValues, setEditValues] = useState({ title: '', author: '', genre: '', isbn: '', total_copies: 1 })

  if (!books || books.length === 0) {
    return <p>Keine Bücher gefunden.</p>
  }

  async function handleDelete(id) {
    const ok = window.confirm('Bist du sicher, dass du dieses Buch löschen möchtest?')
    if (!ok) return
    try {
      const token = localStorage.getItem('token')
      const res = await fetch(`http://localhost:5000/books/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })
      if (res.status === 204) {
        onDelete && onDelete(id)
      } else {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Löschen fehlgeschlagen')
      }
    } catch (err) {
      alert('Netzwerkfehler')
    }
  }

  function handleBorrow(book) {
    onBorrow && onBorrow(book)
  }

  function handleReturn(book) {
    onReturn && onReturn(book)
  }

  function startEdit(book) {
    setEditingId(book.id)
    setEditValues({
      title: book.title || '',
      author: book.author || '',
      genre: book.genre || '',
      isbn: book.isbn || '',
      total_copies: book.total_copies || 1
    })
  }

  function cancelEdit() {
    setEditingId(null)
  }

  async function saveEdit() {
    if (!onUpdate || !editingId) return
    const ok = await onUpdate(editingId, {
      title: editValues.title,
      author: editValues.author,
      genre: editValues.genre,
      isbn: editValues.isbn,
      total_copies: Number(editValues.total_copies)
    })
    if (ok) setEditingId(null)
  }

  function getCounts(book) {
    const total = book.total_copies || 1
    const borrowed = book.borrowed_count || 0
    return { total, borrowed, available: Math.max(total - borrowed, 0) }
  }

  return (
    <table className="book-table">
      <thead>
        <tr>
          <th>Titel</th>
          <th>Autor</th>
          <th>Genre</th>
          <th>ISBN</th>
          <th>Status</th>
          <th>Aktionen</th>
        </tr>
      </thead>
      <tbody>
        {books.map(b => {
          const counts = getCounts(b)
          const isEditing = editingId === b.id
          return (
            <tr key={b.id}>
              <td className="title-cell">
                {isEditing ? (
                  <input
                    className="edit-input"
                    value={editValues.title}
                    onChange={e => setEditValues(v => ({ ...v, title: e.target.value }))}
                  />
                ) : (
                  b.title
                )}
              </td>
              <td>
                {isEditing ? (
                  <input
                    className="edit-input"
                    value={editValues.author}
                    onChange={e => setEditValues(v => ({ ...v, author: e.target.value }))}
                  />
                ) : (
                  b.author
                )}
              </td>
              <td>
                {isEditing ? (
                  <input
                    className="edit-input"
                    value={editValues.genre}
                    onChange={e => setEditValues(v => ({ ...v, genre: e.target.value }))}
                  />
                ) : (
                  b.genre
                )}
              </td>
              <td>
                {isEditing ? (
                  <input
                    className="edit-input"
                    value={editValues.isbn}
                    onChange={e => setEditValues(v => ({ ...v, isbn: e.target.value }))}
                  />
                ) : (
                  b.isbn
                )}
              </td>
              <td>
                <BookStatus book={b} onReserve={onReserve} onUnreserve={onUnreserve} currentUser={currentUser} />
              </td>
              <td>
                {isAdmin && (
                  <div className="action-stack">
                    {!isEditing && counts.available > 0 && (
                      <button onClick={() => handleBorrow(b)}>Ausleihen</button>
                    )}
                    {!isEditing && counts.borrowed > 0 && (
                      <button onClick={() => handleReturn(b)}>Rückgabe</button>
                    )}
                    {isEditing ? (
                      <div className="action-stack">
                        <div>
                          <label>Bestand</label>
                          <input
                            className="edit-input"
                            type="number"
                            min="1"
                            value={editValues.total_copies}
                            onChange={e => setEditValues(v => ({ ...v, total_copies: e.target.value }))}
                          />
                        </div>
                        <button onClick={saveEdit}>Speichern</button>
                        <button onClick={cancelEdit}>Abbrechen</button>
                      </div>
                    ) : (
                      <button onClick={() => startEdit(b)}>Bearbeiten</button>
                    )}
                    {!isEditing && (
                      <button onClick={() => handleDelete(b.id)}>Löschen</button>
                    )}
                  </div>
                )}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
