import React from 'react'

export default function Filter({ filters, onChange, onClear }) {
  return (
    <form className="filter-form" onSubmit={e => e.preventDefault()}>
      <div className="field">
        <label>Title</label>
        <input
          type="text"
          value={filters.title}
          onChange={e => onChange('title', e.target.value)}
          placeholder="Buchtitel eingeben"
        />
      </div>

      <div className="field">
        <label>Author</label>
        <input
          type="text"
          value={filters.author}
          onChange={e => onChange('author', e.target.value)}
          placeholder="Autor"
        />
      </div>

      <div className="field">
        <label>Genre</label>
        <input
          type="text"
          value={filters.genre}
          onChange={e => onChange('genre', e.target.value)}
          placeholder="Genre"
        />
      </div>

      <div className="field">
        <label>ISBN</label>
        <input
          type="text"
          value={filters.isbn}
          onChange={e => onChange('isbn', e.target.value)}
          placeholder="ISBN"
        />
      </div>

      <div className="actions">
        <button type="button" onClick={onClear}>Clear</button>
      </div>
    </form>
  )
}
