/** Small monotonic request gate for non-authoritative React presentation data.
 * A response may update state only when its token is still current. */
export class RequestGenerationGate {
  private generation = 0;

  begin(): number {
    this.generation += 1;
    return this.generation;
  }

  invalidate(): void {
    this.generation += 1;
  }

  isCurrent(token: number): boolean {
    return token === this.generation;
  }
}
