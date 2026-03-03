let lastKnownValue: bigint | null = null;

/**
 * Handle a counter value update from polling.
 * Replace this with your own logic — e.g. send notifications,
 * trigger other contract calls, update a database, etc.
 */
export async function handleCounterEvent(currentValue: bigint): Promise<void> {
  if (lastKnownValue === null) {
    console.log(`📊 Initial counter value: ${currentValue}`);
  } else if (currentValue !== lastKnownValue) {
    console.log(
      `📊 Counter changed: ${lastKnownValue} → ${currentValue}`,
    );
    // TODO: Add your custom logic here
    // - Send a webhook notification
    // - Trigger a follow-up transaction
    // - Write to a database
  }

  lastKnownValue = currentValue;
}
