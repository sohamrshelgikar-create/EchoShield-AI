import { useCallback, useState } from 'react'

const KEY = 'echoshield.history.v1'
const LIMIT = 5

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY))
    return Array.isArray(raw) ? raw.slice(0, LIMIT) : []
  } catch {
    return []
  }
}

function save(items) {
  try {
    localStorage.setItem(KEY, JSON.stringify(items))
  } catch {
    /* storage full or blocked: history is a convenience, so fail quietly */
  }
}

export function useHistory() {
  const [items, setItems] = useState(load)

  const add = useCallback((message, result) => {
    setItems((prev) => {
      const entry = { id: Date.now(), at: new Date().toISOString(), message, result }
      const next = [entry, ...prev.filter((p) => p.message !== message)].slice(0, LIMIT)
      save(next)
      return next
    })
  }, [])

  const clear = useCallback(() => {
    setItems([])
    save([])
  }, [])

  return { items, add, clear }
}
