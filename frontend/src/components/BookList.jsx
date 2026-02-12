import React from 'react'

export default function BookList({ books }) {
  if (!books || books.length === 0) {
    return <p>Keine Bücher gefunden.</p>
  }

  return (
    <table className="book-table">
      <thead>
        <tr>
          <th>Titel</th>
          <th>Autor</th>
          <th>Genre</th>
          <th>ISBN</th>
        </tr>
      </thead>
      <tbody>
        {books.map(b => (
          <tr key={b.id}>
            <td>{b.title}</td>
            <td>{b.author}</td>
            <td>{b.genre}</td>
            <td>{b.isbn}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
