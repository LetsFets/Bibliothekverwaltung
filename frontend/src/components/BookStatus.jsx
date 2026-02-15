import React from 'react'

function parseDate(value) {
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return date
}

function isFuture(value) {
  const date = parseDate(value)
  return date ? date.getTime() > Date.now() : false
}

function formatDate(value) {
  const date = parseDate(value)
  if (!date) return '-'
  return date.toLocaleDateString('de-DE')
}

export default function BookStatus({ book, onReserve, onUnreserve, currentUser }) {
  const borrowedActive = isFuture(book.borrowed_until)
  const reservedActive = isFuture(book.reserved_until)
  const reservedByMe = reservedActive && currentUser && book.reserved_by === currentUser.id

  let statusText = 'Verfügbar'
  if (borrowedActive) {
    statusText = `Ausgeliehen bis ${formatDate(book.borrowed_until)}`
  } else if (reservedActive) {
    statusText = reservedByMe
      ? `Von dir reserviert bis ${formatDate(book.reserved_until)}`
      : `Reserviert bis ${formatDate(book.reserved_until)}`
  }

  const canReserve = !!onReserve && !reservedActive && !borrowedActive
  const canPreorder = !!onReserve && !reservedActive && borrowedActive
  const reserveLabel = borrowedActive ? 'Vormerken' : 'Reservieren'

  return (
    <div className="status-block">
      <div className={`status-pill ${borrowedActive ? 'borrowed' : reservedActive ? 'reserved' : 'available'}`}>
        {statusText}
      </div>
      {borrowedActive && reservedActive && (
        <div className="status-note">
          Reservierung aktiv bis {formatDate(book.reserved_until)}
        </div>
      )}
      {(canReserve || canPreorder) && (
        <button type="button" onClick={() => onReserve(book)}>
          {reserveLabel}
        </button>
      )}
      {!canReserve && reservedActive && !reservedByMe && (
        <div className="status-note">Bereits reserviert</div>
      )}
      {!canReserve && reservedActive && reservedByMe && !borrowedActive && (
        <div className="status-note">Deine Reservierung ist aktiv</div>
      )}
      {reservedByMe && onUnreserve && (
        <button type="button" onClick={() => onUnreserve(book)} className="btn-small">
          Aufheben
        </button>
      )}
    </div>
  )
}
