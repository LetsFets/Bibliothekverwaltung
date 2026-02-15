import React from 'react'
import BookStatus from './BookStatus'

function isFuture(value) {
  if (!value) return false
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return false
  return date.getTime() > Date.now()
}

export default function BookList({ books, isAdmin, onDelete, onReserve, currentUser, onBorrow, onReturn }) {
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
        {books.map(b => (
          <tr key={b.id}>
            <td className="title-cell">{b.title}</td>
            <td>{b.author}</td>
            <td>{b.genre}</td>
            <td>{b.isbn}</td>
            <td>
              <BookStatus book={b} onReserve={onReserve} currentUser={currentUser} />
            </td>
            <td>
              {isAdmin && (
                <div className="action-stack">
                  {isFuture(b.borrowed_until) ? (
                    <button onClick={() => handleReturn(b)}>Rueckgabe</button>
                  ) : (
                    <button onClick={() => handleBorrow(b)}>Ausleihen (2 Wochen)</button>
                  )}
                  <button onClick={() => handleDelete(b.id)}>Loeschen</button>
                </div>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
