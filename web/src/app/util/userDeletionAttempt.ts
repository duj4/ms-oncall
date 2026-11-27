import { isResourceUUID } from './integrationKeyDeletion'

// Keep a sent User deletion unresolved across dialog/route/scope remounts and
// reloads in this tab. This is a retry interlock, never a success receipt.
// Persist only the safe User UUID and a constant marker, never session data.
const pending = new Set<string>()
const storageKey = (id: string): string => 'user-deletion-unresolved:' + id
export function userDeletionUnresolved(id: string): boolean {
  return (
    pending.has(id) || window.sessionStorage.getItem(storageKey(id)) !== null
  )
}
export function beginUserDeletion(id: string): boolean {
  if (!isResourceUUID(id) || userDeletionUnresolved(id)) return false
  window.sessionStorage.setItem(storageKey(id), 'sent')
  if (window.sessionStorage.getItem(storageKey(id)) !== 'sent')
    throw new Error('Deletion safety marker was not retained')
  pending.add(id)
  return true
}
export function finishUserDeletion(id: string, authoritative: boolean): void {
  // A lost response leaves the marker intact, including when its controller
  // has unmounted. Only a classified pre-commit rejection or true receipt can
  // release it. Storage failure retains the in-memory interlock.
  if (!authoritative) return
  try {
    window.sessionStorage.removeItem(storageKey(id))
    pending.delete(id)
  } catch {
    // Keep the conservative interlock if durable state cannot be cleared.
  }
}
