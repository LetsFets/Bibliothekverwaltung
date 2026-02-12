import React from 'react'

export default function BookList({ books, isAdmin, onDelete }) {
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

  return (
    <table className="book-table">
      <thead>
        <tr>
          <th>Titel</th>
          <th>Autor</th>
          <th>Genre</th>
          <th>ISBN</th>
          {isAdmin && <th>Aktionen</th>}
        </tr>
      </thead>
      <tbody>
        {books.map(b => (
          <tr key={b.id}>
            <td className="title-cell">{b.title}</td>
            <td>{b.author}</td>
            <td>{b.genre}</td>
            <td>{b.isbn}</td>
            {isAdmin && (
              <td>
                <button onClick={() => handleDelete(b.id)}>Löschen</button>
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
