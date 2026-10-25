export function requiresRetentionConfirmation(currentDays: number, nextDays: number) {
  return nextDays < currentDays;
}
