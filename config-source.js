import { DEFAULT_GUARDED_TOOL_NAMES } from './tool-adapters.js'

/** Mutable pointer to the configuration currently authoritative for the plugin. */
export function createConfigSource(entry) {
  let current = () => entry
  return {
    get: () => current(),
    setSource(next) {
      if (typeof next !== 'function') throw new TypeError('configuration source must be a function')
      current = next
    },
  }
}

/** Tool names guarded by one config, including the official structured editor. */
export function guardedToolNames(config) {
  const names = Array.isArray(config?.toolNames) ? config.toolNames : []
  const normalized = names
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim().toLowerCase())
  return new Set(normalized.length > 0 ? normalized : DEFAULT_GUARDED_TOOL_NAMES)
}
