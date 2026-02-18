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
  const totalCopies = book.total_copies || 1
  const borrowedCount = book.borrowed_count || (isFuture(book.borrowed_until) ? 1 : 0)

  const reservations = Array.isArray(book.reservations) ? [...book.reservations] : []
  reservations.sort((a, b) => new Date(a.reserved_until).getTime() - new Date(b.reserved_until).getTime())
  const reservationCount = reservations.length
  const availableCount = Math.max(totalCopies - borrowedCount - reservationCount, 0)

  const borrowedActive = borrowedCount > 0
  const reservedActive = reservationCount > 0
  const reservedByMe = reservedActive && currentUser && reservations.some(r => r.user_id === currentUser.id)

  let statusText = 'Verfügbar'
  if (availableCount > 0) {
    statusText = `Verfügbar (${availableCount}/${totalCopies})`
  } else if (borrowedActive) {
    statusText = `Ausgeliehen bis ${formatDate(book.borrowed_until)}`
  } else if (reservedActive) {
    statusText = 'Reserviert'
  }

  const canReserve = !!onReserve && reservationCount < totalCopies
  const reserveLabel = borrowedActive ? 'Vormerken' : 'Reservieren'

  return (
    <div className="status-block">
      <div className={`status-pill ${availableCount > 0 ? 'available' : borrowedActive ? 'borrowed' : reservedActive ? 'reserved' : 'available'}`}>
        {statusText}
      </div>
      <div className="status-note">Bestand: {availableCount}/{totalCopies}</div>
      {reservedActive && reservations.slice(0, 2).map((r, idx) => (
        <div className="status-note" key={`${r.id || r.user_id}-${idx}`}>
          Reservierung {idx + 1} bis {formatDate(r.reserved_until)}
        </div>
      ))}
      {canReserve && (
        <button type="button" onClick={() => onReserve(book)}>
          {reserveLabel}
        </button>
      )}
      {!canReserve && reservedActive && !reservedByMe && (
        <div className="status-note">Bereits reserviert</div>
      )}
      {!canReserve && reservedActive && reservedByMe && availableCount > 0 && (
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
