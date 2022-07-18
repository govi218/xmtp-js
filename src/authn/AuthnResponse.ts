import { Reader } from 'protobufjs/minimal'

import * as proto from '../proto/authn'

export class AuthnResponse {
  public constructor(public proto: proto.ClientAuthnResponse) {
    this.proto = proto
  }

  static create(authnSuccessful: boolean, errorStr: string): AuthnResponse {
    return new AuthnResponse({
      v1: {
        authnSuccessful: authnSuccessful,
        errorStr: errorStr,
      },
    })
  }

  static decode(bytes: Uint8Array): AuthnResponse {
    const res = proto.ClientAuthnResponse.decode(Reader.create(bytes))
    return new AuthnResponse(res)
  }

  encode(): Uint8Array {
    return proto.ClientAuthnResponse.encode(this.proto).finish()
  }

  isSuccess(): boolean {
    if (this.proto.v1) {
      return this.proto.v1.authnSuccessful
    }

    throw new Error('unsupported response version')
  }

  getErrorStr(): string {
    if (this.proto.v1) {
      return this.proto.v1.authnSuccessful ? '' : this.proto.v1.errorStr
    }

    throw new Error('unsupported response version')
  }
}
