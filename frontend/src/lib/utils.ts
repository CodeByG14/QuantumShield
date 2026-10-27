type ClassValue = string | number | boolean | undefined | null | ClassValue[]

/**
 * Simple className utility for conditional classes
 * Similar to clsx but without external dependency
 */
export function cn(...inputs: ClassValue[]): string {
  return inputs
    .flat()
    .filter((x) => typeof x === 'string')
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim()
}
