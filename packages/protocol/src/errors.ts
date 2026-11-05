/** Thrown when bytes or JSON received from the network do not match the protocol. */
export class ProtocolError extends Error {
  override readonly name = 'ProtocolError';
  constructor(
    message: string,
    readonly issues?: readonly string[],
  ) {
    super(message);
  }
}
