/** App clock. The demo build moves it back to the end of the sample logs so "5 minutes ago" stays true. */
let offset = 0;
export const setClockOffset = (ms: number) => { offset = ms; };
export const now = () => Date.now() + offset;
