import * as proto from '../src/proto/messaging'
import { PublicKeyBundle } from './crypto'
import PublicKey from './crypto/PublicKey'

// ContactBundle packages all the infromation which a client uses to advertise on the network.
export default class ContactBundle implements proto.ContactBundleV1 {
  keyBundle: PublicKeyBundle

  constructor(publicKeyBundle: PublicKeyBundle) {
    if (!publicKeyBundle) {
      throw new Error('missing keyBundle')
    }
    this.keyBundle = publicKeyBundle
  }

  toBytes(): Uint8Array {
    return proto.ContactBundle.encode({
      v1: {
        keyBundle: this.keyBundle,
      },
    }).finish()
  }

  static fromBytes(bytes: Uint8Array): ContactBundle {
    let decoded: proto.ContactBundle | undefined
    try {
      decoded = proto.ContactBundle.decode(bytes)
    } catch (e) {
      if (e instanceof RangeError) {
        return this.fromBytesLegacy(bytes)
      }

      // Re-throw other errors
      throw e
    }

    if (!decoded.v1?.keyBundle?.identityKey) {
      throw new Error('missing keyBundle')
    }
    if (!decoded.v1?.keyBundle?.preKey) {
      throw new Error('missing pre-key')
    }
    return new ContactBundle(
      new PublicKeyBundle(
        new PublicKey(decoded.v1?.keyBundle?.identityKey),
        new PublicKey(decoded.v1?.keyBundle?.preKey)
      )
    )
  }

  private static fromBytesLegacy(bytes: Uint8Array): ContactBundle {
    const keyBundle = proto.PublicKeyBundle.decode(bytes)

    if (!keyBundle?.preKey || !keyBundle?.identityKey) {
      throw new Error('bad legacy key bundle')
    }

    return new ContactBundle(
      new PublicKeyBundle(
        new PublicKey(keyBundle?.identityKey),
        new PublicKey(keyBundle?.preKey)
      )
    )
  }
}
